package pcloud

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// DecryptFolderKey decrypts a folder's Content Encryption Key (CEK) using RSA-OAEP (SHA-1).
// Provided in crypto.go originally; kept here to ensure availability while crypto.go is being cleaned.
func (kp *KeyPair) DecryptFolderKey(encryptedKey string) (*FolderKey, error) {
	if kp.RSAPriv == nil {
		return nil, errors.New("private key not loaded")
	}
	priv, ok := kp.RSAPriv.(*rsa.PrivateKey)
	if !ok || priv == nil {
		return nil, errors.New("invalid RSA private key type")
	}
	enc, err := base64URLDecode(encryptedKey)
	if err != nil {
		return nil, err
	}
	dec, err := rsa.DecryptOAEP(sha1.New(), nil, priv, enc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt folder key: %w", err)
	}
	if len(dec) < 41 {
		return nil, errors.New("decrypted folder key too short")
	}
	return &FolderKey{
		Type:    binary.LittleEndian.Uint32(dec[0:4]),
		Flags:   binary.LittleEndian.Uint32(dec[4:8]),
		AESKey:  dec[8:40],
		HMACKey: dec[40:],
	}, nil
}

// VerifyEncryptedCEKForThisUser returns true if the given base64url-encoded RSA-OAEP
// encrypted CEK can be decrypted using this user's private key. This effectively
// verifies the CEK was wrapped for the user's public key ("derived from master key"
// in the sense of belonging to this keypair).
func (kp *KeyPair) VerifyEncryptedCEKForThisUser(encryptedKey string) bool {
	if kp == nil || kp.RSAPriv == nil {
		return false
	}
	priv, ok := kp.RSAPriv.(*rsa.PrivateKey)
	if !ok || priv == nil {
		return false
	}
	enc, err := base64URLDecode(encryptedKey)
	if err != nil {
		return false
	}
	dec, err := rsa.DecryptOAEP(sha1.New(), nil, priv, enc, nil)
	if err != nil {
		return false
	}
	// Minimal sanity: expect at least 8(header) + 32 + 32 bytes
	if len(dec) < 72 {
		return false
	}
	// Additional structure checks
	aesLen := len(dec) - 8
	if aesLen < 64 {
		return false
	}
	return true
}

// EncryptFolderKey encrypts a folder or file Content Encryption Key (CEK)
// using RSA-OAEP (SHA-1) with the user's public key and encodes it as base64url.
// The input key fields are serialized as:
//
//	Type(4,LE) || Flags(4,LE) || AESKey(32) || HMACKey(32)
func (kp *KeyPair) EncryptFolderKey(key FolderKey) (string, error) {
	if kp.RSAPub == nil {
		return "", errors.New("public key not loaded")
	}
	pub, ok := kp.RSAPub.(*rsa.PublicKey)
	if !ok || pub == nil {
		return "", errors.New("invalid RSA public key type")
	}
	// Serialize CEK
	buf := make([]byte, 0, 8+32+32)
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, key.Type)
	buf = append(buf, tmp...)
	binary.LittleEndian.PutUint32(tmp, key.Flags)
	buf = append(buf, tmp...)
	if len(key.AESKey) != 32 || len(key.HMACKey) != 32 {
		return "", fmt.Errorf("invalid key lengths: aes=%d hmac=%d", len(key.AESKey), len(key.HMACKey))
	}
	buf = append(buf, key.AESKey...)
	buf = append(buf, key.HMACKey...)

	enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, buf, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt folder key: %w", err)
	}
	return base64URLEncode(enc), nil
}

// GenerateFileKey creates a random file Content Encryption Key (CEK).
// Type is set to 1 and Flags to 0 by convention.
func (kp *KeyPair) GenerateFileKey() (*FolderKey, error) {
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("rand AES key: %w", err)
	}
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("rand HMAC key: %w", err)
	}
	fk := &FolderKey{Type: 1, Flags: 0, AESKey: aesKey, HMACKey: hmacKey}
	return fk, nil
}

// DecryptFileContents decrypts encrypted file data using the file's Content Encryption Key.
// Layout (per pcrypto.js): Type(4,LE) + Flags(4,LE) + IV(16) + Ciphertext + Trailer(14+16k?) + HMAC(64)
// Ciphertext starts at offset 24, uses AES-256-CBC with PKCS7 padding.
func DecryptFileContents(encryptedData []byte, fileKey FolderKey) ([]byte, error) {
	// Implement exact sector-based decryption per pcrypto.js
	offs := computeCipherOffsets(len(encryptedData))
	if offs.plainSize < 0 || offs.sectors < 0 {
		return nil, fmt.Errorf("invalid offsets for size=%d", len(encryptedData))
	}
	out := make([]byte, 0, offs.plainSize)

	sector := 0
	for sector < offs.sectors {
		// Determine chunk covering up to TREE_SECTORS sectors
		chunk := cipherDownloadOffset(sector, &offs)
		if chunk.offset < 0 || chunk.end > len(encryptedData) || chunk.offset >= chunk.end {
			return nil, fmt.Errorf("invalid chunk offsets: %v (%d)", chunk, len(encryptedData))
		}
		// Level-0 auth position and per-chunk accounting
		a0 := authSectorOffset(sector, 0, &offs)
		// number of sectors available from this auth window starting at current sector
		d := a0.length/AuthSize - a0.authID
		if d <= 0 {
			return nil, fmt.Errorf("bad auth window d=%d at sector=%d", d, sector)
		}
		// p = data length for this chunk up to first level-0 auth
		p := a0.offset - chunk.offset

		// Process up to d sectors in this chunk
		for y := 0; y < d && sector+y < offs.sectors; y++ {
			// Compute sector length f
			f := SectorSize
			if !(a0.offset == SectorSize*TreeSectors || y != d-1) {
				f = p - y*SectorSize
				if f < 0 {
					return nil, fmt.Errorf("negative sector length at sector=%d", sector+y)
				}
			}
			dataStart := chunk.offset + y*SectorSize
			dataEnd := dataStart + f
			if dataStart < 0 || dataEnd > len(encryptedData) {
				return nil, fmt.Errorf("data slice OOB sector=%d [%d:%d] size=%d", sector+y, dataStart, dataEnd, len(encryptedData))
			}
			c := encryptedData[dataStart:dataEnd]
			// Auth record for this sector at level 0
			authStart := a0.offset + (a0.authID+y)*AuthSize
			authEnd := authStart + AuthSize
			if authEnd > len(encryptedData) {
				return nil, fmt.Errorf("auth slice OOB sector=%d [%d:%d] size=%d", sector+y, authStart, authEnd, len(encryptedData))
			}
			h := encryptedData[authStart:authEnd]

			pt, err := decryptSector(&fileKey, c, h, uint64(sector+y))
			if err != nil {
				return nil, fmt.Errorf("decrypt sector %d: %w", sector+y, err)
			}
			out = append(out, pt...)
		}

		sector += TreeSectors
	}

	if len(out) != offs.plainSize {
		// Truncate in case of over-accumulation due to rounding
		if len(out) > offs.plainSize {
			out = out[:offs.plainSize]
		}
	}
	return out, nil
}

// (helper decryptCBC removed; no direct callers)

// ===== Encryption (pcrypto.js parity) =====

// computeCipherSizeFromPlain returns the total ciphertext size including all auth levels
// for a given plaintext size, mirroring pcrypto.js tree layout.
func computeCipherSizeFromPlain(plainSize int) int {
	if plainSize <= 0 {
		return 0
	}
	sectors := (plainSize + SectorSize - 1) / SectorSize
	total := plainSize
	n := sectors
	for {
		total += n * AuthSize
		if n <= 1 {
			break
		}
		n = (n + TreeSectors - 1) / TreeSectors
	}
	return total
}

// aesECBEncrypt32 encrypts 32 bytes using AES-ECB (two blocks)
func aesECBEncrypt32(block cipher.Block, src []byte) []byte {
	if len(src) != 32 {
		panic("aesECBEncrypt32: src must be 32 bytes")
	}
	out := make([]byte, 32)
	block.Encrypt(out[:16], src[:16])
	block.Encrypt(out[16:], src[16:])
	return out
}

func uint64ToLEBytes(n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return b
}

// encryptSector performs sector encryption and returns (cipherData, auth32)
func encryptSector(key *FolderKey, plain []byte, sectorID uint64) ([]byte, []byte, error) {
	blk, err := aes.NewCipher(key.AESKey)
	if err != nil {
		return nil, nil, err
	}
	// Choose random o (16 bytes)
	o := make([]byte, 16)
	if _, err := rand.Read(o); err != nil {
		return nil, nil, err
	}
	// Compute f = HMAC_SHA512(plain || sectorID_le || o)[:16]
	sid := uint64ToLEBytes(sectorID)
	mac := hmac.New(sha512.New, key.HMACKey)
	mac.Write(plain)
	mac.Write(sid)
	mac.Write(o)
	sum := mac.Sum(nil)
	f := sum[:16]

	// Build auth n = o[:8] || f || o[8:]
	n := make([]byte, 32)
	copy(n[:8], o[:8])
	copy(n[8:24], f)
	copy(n[24:], o[8:])
	auth := aesECBEncrypt32(blk, n)

	// Encrypt sector data
	var cipherData []byte
	if len(plain) < 16 {
		// Short sector: XOR with o prefix
		e := make([]byte, len(plain))
		for i := 0; i < len(plain); i++ {
			e[i] = o[i] ^ plain[i]
		}
		cipherData = e
		return cipherData, auth, nil
	}

	u := len(plain) % 16
	l := len(plain) - u
	// When u==0, all blocks are handled by CBC with IV=f
	if u == 0 {
		ePart := make([]byte, l)
		cipher.NewCBCEncrypter(blk, f).CryptBlocks(ePart, plain[:l])
		return ePart, auth, nil
	}
	// For u>0, CBC-encrypt all but the last full block; that last full block
	// is incorporated into the special tail construction with the u-byte suffix.
	preLen := l - 16
	var ePart []byte
	if preLen > 0 {
		ePart = make([]byte, preLen)
		cipher.NewCBCEncrypter(blk, f).CryptBlocks(ePart, plain[:preLen])
	} else {
		ePart = nil
	}
	// Tail handling to mirror decrypt logic exactly
	var v []byte
	if preLen > 0 {
		v = ePart[len(ePart)-16:]
	} else {
		v = f
	}
	desiredDec := plain[l-16 : l]
	desiredY := plain[l : l+u]
	// E = ENC(desiredDec XOR v)
	x := make([]byte, 16)
	for i := 0; i < 16; i++ {
		x[i] = desiredDec[i] ^ v[i]
	}
	E := make([]byte, 16)
	blk.Encrypt(E, x)
	// Choose b so that:
	//   b[:u] = desiredY XOR E[:u]
	//   b[u:] = E[u:]
	b := make([]byte, 16)
	for i := 0; i < u; i++ {
		b[i] = desiredY[i] ^ E[i]
	}
	copy(b[u:], E[u:])
	// tail = ENC(b) || E[:u]
	tFirst := make([]byte, 16)
	blk.Encrypt(tFirst, b)
	tTail := append(tFirst, E[:u]...)
	cipherData = append(ePart, tTail...)
	return cipherData, auth, nil
}

// EncryptFileContentsFromPlain encrypts a plaintext buffer into pCloud Crypto format.
// It fills level-0 auth records correctly. Higher-level auth windows are reserved but left zeroed.
func EncryptFileContentsFromPlain(plain []byte, key FolderKey) ([]byte, error) {
	plainSize := len(plain)
	if plainSize == 0 {
		return []byte{}, nil
	}
	cipherSize := computeCipherSizeFromPlain(plainSize)
	buf := make([]byte, cipherSize)

	// Compute offsets structure from total cipher size
	offs := computeCipherOffsets(cipherSize)
	sectors := (plainSize + SectorSize - 1) / SectorSize
	for s := 0; s < sectors; s++ {
		// Sector plaintext slice
		start := s * SectorSize
		end := start + SectorSize
		if end > plainSize {
			end = plainSize
		}
		p := plain[start:end]
		// Encrypt sector
		cd, h, err := encryptSector(&key, p, uint64(s))
		if err != nil {
			return nil, fmt.Errorf("encrypt sector %d: %w", s, err)
		}
		// Place data
		dataStart := dataCipherOffsetBySectorid(s)
		copy(buf[dataStart:dataStart+len(cd)], cd)
		// Place level-0 auth
		a0 := authSectorOffset(s, 0, &offs)
		authStart := a0.offset + a0.authID*AuthSize
		copy(buf[authStart:authStart+AuthSize], h)
	}
	// Build higher-level auth tree (levels 1..treeLevels), including top/master auth
	if err := buildAuthTree(buf, &offs, &key); err != nil {
		return nil, err
	}
	return buf, nil
}

// ===== Exact sector crypto (pcrypto.js parity) =====

const (
	SectorSize  = 4096
	AuthSize    = 32
	TreeSectors = 128
)

// Offsets structure mirrors pcrypto.js offset_template
type cipherOffsetsInfo struct {
	needMasterAuth   bool
	masterAuthOffset int
	plainSize        int
	sectors          int
	cipherSize       int
	treeLevels       int
	lastAuthOffset   []int
	lastAuthLength   []int
}

func offsetTemplate() cipherOffsetsInfo {
	return cipherOffsetsInfo{
		lastAuthOffset: make([]int, 0),
		lastAuthLength: make([]int, 0),
	}
}

// Max level sizes from pcrypto.js
var maxLevelSize = []int{
	4096,
	528384,
	67637248,
	8657571840,
	1108169199616,
	0x810204081000,
	0x40810204081000,
}

// computeCipherOffsets replicates pcrypto.js cipherOffsets(size)
func computeCipherOffsets(cipherSize int) cipherOffsetsInfo {
	n := offsetTemplate()
	if cipherSize <= AuthSize {
		return n
	}

	n.cipherSize = cipherSize
	n.needMasterAuth = cipherSize > SectorSize+AuthSize
	t := cipherSize - AuthSize
	if n.needMasterAuth {
		n.masterAuthOffset = t
	} else {
		n.masterAuthOffset = t + AuthSize
	}

	// Determine tree level i where t <= MAX_LEVEL_SIZE[i]
	i := 0
	for i < len(maxLevelSize) && !(t <= maxLevelSize[i]) {
		i++
	}
	e := t
	n.treeLevels = i
	n.ensureLevels(i + 1)
	n.lastAuthOffset[i] = e
	n.lastAuthLength[i] = AuthSize
	for i > 0 {
		i--
		r := (t + maxLevelSize[i] + AuthSize - 1) / (maxLevelSize[i] + AuthSize)
		t -= r * AuthSize
		r %= TreeSectors
		if r == 0 {
			r = TreeSectors
		}
		e -= r * AuthSize
		n.lastAuthOffset[i] = e
		n.lastAuthLength[i] = r * AuthSize
	}
	n.plainSize = t
	n.sectors = (t + SectorSize - 1) / SectorSize
	return n
}

func (n *cipherOffsetsInfo) ensureLevels(levels int) {
	if len(n.lastAuthOffset) < levels {
		pad := make([]int, levels)
		copy(pad, n.lastAuthOffset)
		n.lastAuthOffset = pad
	}
	if len(n.lastAuthLength) < levels {
		pad := make([]int, levels)
		copy(pad, n.lastAuthLength)
		n.lastAuthLength = pad
	}
}

// levelAuthOffset mirrors pcrypto.js levelAuthOffset(t, e)
func levelAuthOffset(level int, e int) int {
	r := maxLevelSize[level+1]*(e+1) - SectorSize
	for e >= TreeSectors {
		e = e / TreeSectors
		r += e * SectorSize
	}
	return r
}

// dataCipherOffsetBySectorid mirrors pcrypto.js
func dataCipherOffsetBySectorid(t int) int {
	e := t * SectorSize
	for t >= TreeSectors {
		t = t / TreeSectors
		e += t * SectorSize
	}
	return e
}

type blockRange struct {
	offset int
	end    int
	length int
}

// cipherDownloadOffset mirrors pcrypto.js cipherDownloadOffset
func cipherDownloadOffset(t int, n *cipherOffsetsInfo) blockRange {
	r := dataCipherOffsetBySectorid(t)
	i := dataCipherOffsetBySectorid(t + TreeSectors)
	if t+TreeSectors > n.sectors {
		i = n.cipherSize
	}
	return blockRange{offset: r, end: i, length: i - r}
}

// getLastSectoridBySize mirrors pcrypto.js
func getLastSectoridBySize(t int) int {
	if t == 0 {
		return 0
	}
	return (t - 1) / SectorSize
}

type authWindow struct {
	offset int
	length int
	authID int
}

// authSectorOffset mirrors pcrypto.js authSectorOffset(t, e, r)
func authSectorOffset(t int, level int, n *cipherOffsetsInfo) authWindow {
	i := getLastSectoridBySize(n.plainSize) / TreeSectors
	nn := t / TreeSectors
	s := t % TreeSectors
	for o := 0; o < level; o++ {
		i = i / TreeSectors
		s = nn % TreeSectors
		nn = nn / TreeSectors
	}
	var a, f int
	if nn == i {
		n.ensureLevels(level + 1)
		a = n.lastAuthOffset[level]
		f = n.lastAuthLength[level]
	} else {
		a = levelAuthOffset(level, nn)
		f = SectorSize
	}
	return authWindow{offset: a, length: f, authID: s}
}

// decryptSector implements pcrypto.js decryptSector for one sector
func decryptSector(key *FolderKey, cipherData, auth []byte, sectorID uint64) ([]byte, error) {
	if len(auth) != 32 {
		return nil, fmt.Errorf("auth length %d != 32", len(auth))
	}
	// n = AES-ECB-DEC(auth, AESKey)
	blk, err := aes.NewCipher(key.AESKey)
	if err != nil {
		return nil, err
	}
	n := make([]byte, 32)
	// ECB decrypt 32 bytes = two blocks
	blk.Decrypt(n[:16], auth[:16])
	blk.Decrypt(n[16:], auth[16:])

	o := append([]byte{}, n[0:8]...)
	o = append(o, n[24:]...)
	f := append([]byte{}, n[8:24]...)

	var p []byte
	e := cipherData
	if len(e) < 16 {
		p = xorBytesLimit(o, e, len(e))
		o = append(append([]byte{}, e...), o[len(e):]...)
	} else {
		var u int
		var tail []byte
		if len(e)%16 != 0 {
			u = len(e) % 16
			l := len(e) - 16 - u
			tail = append([]byte{}, e[l:]...)
			e = e[:l]
		}
		if len(e) > 0 {
			// CBC decrypt with IV=f
			pt := make([]byte, len(e))
			cipher.NewCBCDecrypter(blk, f).CryptBlocks(pt, e)
			p = append(p, pt...)
		}
		if tail != nil {
			var v []byte
			if len(e) > 0 {
				v = e[len(e)-16:]
			} else {
				v = f
			}
			b := make([]byte, 16)
			blk.Decrypt(b, tail[:16])
			y := xorExact(b[:u], tail[16:])
			g := append([]byte{}, tail[16:]...)
			g = append(g, b[u:]...)
			dec := make([]byte, 16)
			cipher.NewCBCDecrypter(blk, v).CryptBlocks(dec, g)
			p = append(p, dec...)
			p = append(p, y...)
		}
	}

	// Verify HMAC
	// w = m || uint64(sectorID LE) || o
	sid := uint64ToLEBytes(sectorID)
	w := make([]byte, 0, len(p)+8+len(o))
	w = append(w, p...)
	w = append(w, sid...)
	w = append(w, o...)
	mac := hmac.New(sha512.New, key.HMACKey)
	mac.Write(w)
	sum := mac.Sum(nil)
	if !hmac.Equal(sum[:16], f) {
		return nil, errors.New("sector auth compare fail")
	}
	return p, nil
}

func xorBytesLimit(a, b []byte, n int) []byte {
	if len(a) < n || len(b) < n {
		n = min(len(a), len(b))
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func xorExact(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xorBytes length mismatch")
	}
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func powInt(a, b int) int {
	p := 1
	for i := 0; i < b; i++ {
		p *= a
	}
	return p
}

// buildAuthTree computes higher-level auth records from level 1 up to the top level.
// For level L>=1, each auth is derived from HMAC-SHA512 over the child window bytes
// (concatenation of level L-1 auth records for that group). It writes AES-ECB-ENC(HMAC[:32]) at the
// appropriate offsets, matching pcrypto.js signSectorAuth.
func buildAuthTree(buf []byte, offs *cipherOffsetsInfo, key *FolderKey) error {
	if offs.sectors == 0 {
		return nil
	}
	blk, err := aes.NewCipher(key.AESKey)
	if err != nil {
		return err
	}
	totalSectors := offs.sectors
	// Iterate levels 1..treeLevels (inclusive), level 0 already filled
	for level := 1; level <= offs.treeLevels; level++ {
		groupSectors := powInt(TreeSectors, level)
		childGroupSectors := powInt(TreeSectors, level-1)
		groups := (totalSectors + groupSectors - 1) / groupSectors
		for g := 0; g < groups; g++ {
			startSector := g * groupSectors
			endSector := startSector + groupSectors
			if endSector > totalSectors {
				endSector = totalSectors
			}
			// Number of child auth entries included
			childCount := (endSector - startSector + childGroupSectors - 1) / childGroupSectors
			if childCount <= 0 {
				continue
			}
			// Child window (level-1) position; startSector is aligned to childGroupSectors
			awChild := authSectorOffset(startSector, level-1, offs)
			childOff := awChild.offset + awChild.authID*AuthSize
			childLen := childCount * AuthSize
			if childOff < 0 || childOff+childLen > len(buf) {
				return fmt.Errorf("child window OOB level=%d g=%d off=%d len=%d size=%d", level, g, childOff, childLen, len(buf))
			}
			M := buf[childOff : childOff+childLen]
			// f = HMAC(M)[:32]
			mac := hmac.New(sha512.New, key.HMACKey)
			mac.Write(M)
			sum := mac.Sum(nil)
			f := sum[:32]
			// auth record = AES-ECB(f)
			auth32 := aesECBEncrypt32(blk, f)
			// Parent window (level)
			awParent := authSectorOffset(startSector, level, offs)
			parentOff := awParent.offset + awParent.authID*AuthSize
			if parentOff < 0 || parentOff+AuthSize > len(buf) {
				return fmt.Errorf("parent window OOB level=%d g=%d off=%d size=%d", level, g, parentOff, len(buf))
			}
			copy(buf[parentOff:parentOff+AuthSize], auth32)
		}
	}
	return nil
}

// DecryptFilename reverses EncryptFilename using the folder/file key.
// Input is a Base32 (no padding) encoded string; output is the plaintext filename.
func DecryptFilename(enc string, key FolderKey) (string, error) {
	data, err := base32Decode(enc)
	if err != nil {
		return "", err
	}
	if len(data) == 16 {
		// Single block case: AES-ECB decrypt then XOR with first 16 of HMAC key
		block, err := aes.NewCipher(key.AESKey)
		if err != nil {
			return "", err
		}
		tmp := make([]byte, 16)
		block.Decrypt(tmp, data)
		x := xorBytes(tmp, key.HMACKey[:16])
		return string(removePadding(x)), nil
	}

	if len(data)%16 != 0 || len(data) < 32 {
		return "", fmt.Errorf("invalid encrypted filename length: %d", len(data))
	}
	// Multi-block: decrypt blocks 1..N-1 without needing IV; then derive IV from HMAC of unpadded tail
	nBlocks := len(data) / 16
	block, err := aes.NewCipher(key.AESKey)
	if err != nil {
		return "", err
	}
	// Decrypt tail (blocks 1..N-1)
	tail := make([]byte, (nBlocks-1)*16)
	for i := 1; i < nBlocks; i++ {
		dec := make([]byte, 16)
		block.Decrypt(dec, data[i*16:(i+1)*16])
		// XOR with previous ciphertext block
		prev := data[(i-1)*16 : i*16]
		for j := 0; j < 16; j++ {
			tail[(i-1)*16+j] = dec[j] ^ prev[j]
		}
	}
	// Compute IV from HMAC-SHA512 of unpadded tail
	unpaddedTail := removePadding(tail)
	mac := hmac.New(sha512.New, key.HMACKey)
	mac.Write(unpaddedTail)
	iv := mac.Sum(nil)[:16]

	// Decrypt first block using derived IV
	firstDec := make([]byte, 16)
	block.Decrypt(firstDec, data[0:16])
	first := make([]byte, 16)
	for j := 0; j < 16; j++ {
		first[j] = firstDec[j] ^ iv[j]
	}

	// Combine and strip zero padding
	pt := append(first, tail...)
	pt = removePadding(pt)
	return string(pt), nil
}

// EncryptFilename encrypts a filename using pCloud's encryption scheme.
// The encrypted name is Base32 encoded (upper-case, no padding).
func EncryptFilename(name string, key FolderKey) (string, error) {
	nameBytes := []byte(name)
	aligned := alignTo16(nameBytes)

	if len(aligned) == 16 {
		// Exactly one block: XOR with first 16 bytes of HMAC key, then AES-ECB
		xored := xorBytes(aligned, key.HMACKey[:16])
		block, err := aes.NewCipher(key.AESKey)
		if err != nil {
			return "", err
		}
		out := make([]byte, 16)
		block.Encrypt(out, xored)
		return base32Encode(out), nil
	}

	// Longer: HMAC of unpadded tail (after first 16), IV = first 16 bytes of HMAC; encrypt all with CBC
	dataAfterFirst := aligned[16:]
	unpaddedAfterFirst := removePadding(dataAfterFirst)
	mac := hmac.New(sha512.New, key.HMACKey)
	mac.Write(unpaddedAfterFirst)
	iv := mac.Sum(nil)[:16]
	block, err := aes.NewCipher(key.AESKey)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(aligned))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(out, aligned)
	return base32Encode(out), nil
}

// ParsePrivateKey parses a base64url-encoded pCloud private key blob.
func ParsePrivateKey(encodedKey string) (*ParsedPrivateKey, error) {
	data, err := base64URLDecode(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(data) < 72 {
		return nil, errors.New("private key too short")
	}
	return &ParsedPrivateKey{
		Type:  binary.LittleEndian.Uint32(data[0:4]),
		Flags: binary.LittleEndian.Uint32(data[4:8]),
		Salt:  data[8:72],
		Key:   data[72:],
	}, nil
}

// ParsePublicKey parses a base64url-encoded pCloud public key blob.
func ParsePublicKey(encodedKey string) (*ParsedPublicKey, error) {
	data, err := base64URLDecode(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(data) < 8 {
		return nil, errors.New("public key too short")
	}
	return &ParsedPublicKey{
		Type:  data[0:4],
		Flags: data[4:8],
		Key:   data[8:],
	}, nil
}

// DecryptPrivateKey decrypts the user's private key using their crypto password.
// PBKDF2-HMAC-SHA512 (20000 iters) derives AES key + IV; decrypt with custom PCTR.
func DecryptPrivateKey(password, encodedPrivateKey, encodedPublicKey string) (*KeyPair, error) {
	privKey, err := ParsePrivateKey(encodedPrivateKey)
	if err != nil {
		return nil, err
	}
	pubKey, err := ParsePublicKey(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	derived := pbkdf2.Key([]byte(password), privKey.Salt, 20000, 48, sha512.New)
	aesKey := derived[:32]
	iv := derived[32:48]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	dec := make([]byte, len(privKey.Key))
	decryptPCTR(block, iv, privKey.Key, dec)

	if len(dec) < 4 {
		return nil, errors.New("decrypted key too short")
	}
	// Trim ASN.1 to exact length based on DER header
	var keyLen int
	if dec[1]&0x80 != 0 {
		numLen := int(dec[1] & 0x7F)
		keyLen = 2 + numLen
		for i := 0; i < numLen; i++ {
			keyLen += int(dec[2+i]) << (8 * (numLen - 1 - i))
		}
	} else {
		keyLen = int(dec[1]) + 2
	}
	if keyLen > len(dec) {
		keyLen = len(dec)
	}
	dec = dec[:keyLen]

	rsaPriv, err := x509.ParsePKCS1PrivateKey(dec)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted private key: %w", err)
	}
	rsaPub, err := x509.ParsePKCS1PublicKey(pubKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		RSAPriv:    rsaPriv,
		RSAPub:     rsaPub,
	}, nil
}

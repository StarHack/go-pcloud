package pcloud

import (
	"crypto/cipher"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

// alignTo16 returns a zero-padded copy of data aligned to a 16-byte boundary.
func alignTo16(data []byte) []byte {
	if len(data)%16 == 0 {
		return data
	}
	aligned := make([]byte, ((len(data)/16)+1)*16)
	copy(aligned, data)
	return aligned
}

// xorBytes XORs two equal-length byte slices and returns a new slice.
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xorBytes: lengths must match")
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// removePadding trims trailing zero bytes.
func removePadding(data []byte) []byte {
	end := len(data)
	for end > 0 && data[end-1] == 0 {
		end--
	}
	return data[:end]
}

// removePaddingArray is identical to removePadding (kept for parity with original code names).
func removePaddingArray(data []byte) []byte {
	return removePadding(data)
}

// removePKCS7Padding removes PKCS7 padding from decrypted data.
func removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	// Get the padding length from the last byte
	paddingLen := int(data[len(data)-1])

	// Validate padding length
	if paddingLen == 0 || paddingLen > 16 || paddingLen > len(data) {
		// Invalid padding, might be zero-padding instead
		return removePadding(data)
	}

	// Verify all padding bytes are the same
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			// Not valid PKCS7, try zero-padding
			return removePadding(data)
		}
	}

	return data[:len(data)-paddingLen]
}

// tryRemovePKCS7 attempts strict PKCS7 padding removal and reports validity.
// It does NOT fall back to zero-padding. Returns (trimmed, true) if valid, otherwise (nil, false).
func tryRemovePKCS7(data []byte) ([]byte, bool) {
	if len(data) == 0 {
		return nil, false
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen == 0 || paddingLen > 16 || paddingLen > len(data) {
		return nil, false
	}
	// Verify
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			return nil, false
		}
	}
	return data[:len(data)-paddingLen], true
}

// base32Encode encodes bytes to Base32 without padding and converts to uppercase.
func base32Encode(data []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	return strings.ToUpper(enc)
}

// base32Decode decodes a Base32 string (case-insensitive, no padding required).
func base32Decode(s string) ([]byte, error) {
	s = strings.ToUpper(s)
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// base64URLDecode decodes a base64url string (no padding).
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// base64URLEncode encodes bytes to base64url (no padding).
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// decryptPCTR implements pCloud's custom PCTR (parallel counter) mode used for private key decryption.
func decryptPCTR(block cipher.Block, iv, src, dst []byte) {
	var counter uint32
	for i := 0; i < len(src); i += 16 {
		ctr := make([]byte, 16)
		binary.BigEndian.PutUint32(ctr[0:4], swap32(counter))
		for j := 0; j < 16; j++ {
			ctr[j] ^= iv[j]
		}
		tmp := make([]byte, 16)
		block.Encrypt(tmp, ctr)
		end := i + 16
		if end > len(src) {
			end = len(src)
		}
		for j := i; j < end; j++ {
			dst[j] = tmp[j-i] ^ src[j]
		}
		counter++
	}
}

// swap32 reverses byte order of a 32-bit integer.
func swap32(n uint32) uint32 {
	return (n >> 24) | ((n & 0x00FF0000) >> 8) | ((n & 0x0000FF00) << 8) | ((n & 0x000000FF) << 24)
}

// Types moved here so crypto.go can contain only exported functions.
type FolderKey struct {
	Type    uint32
	Flags   uint32
	AESKey  []byte
	HMACKey []byte
}

type KeyPair struct {
	PrivateKey *ParsedPrivateKey
	PublicKey  *ParsedPublicKey
	RSAPriv    interface{}
	RSAPub     interface{}
}

type ParsedPrivateKey struct {
	Type  uint32
	Flags uint32
	Salt  []byte
	Key   []byte
}

type ParsedPublicKey struct {
	Type  []byte
	Flags []byte
	Key   []byte
}

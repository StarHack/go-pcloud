# pCloud Crypto Implementation

This document describes the complete encryption and decryption implementation used by the pCloud Go client library, which is compatible with pCloud's proprietary "pCloud Crypto" format and tries to give a comprehensive instruction set on how it was done.

- **Author:** StarHack
- **URL:** https://github.com/StarHack/go-pcloud
- **Date:** Nov 23, 2025

## Overview

pCloud Crypto uses a hierarchical encryption scheme with:
- **RSA-OAEP** for key wrapping (asymmetric encryption)
- **AES-256** for data encryption (symmetric encryption)
- **HMAC-SHA512** for integrity verification
- **Base32/Base64URL** encoding for filename and key storage

The system supports both encrypted and plain folders/files, with automatic detection and transparent handling.

## Key Components

### 1. Key Hierarchy

```
Master Key (derived from user password)
    ↓
User RSA Key Pair (2048-bit)
    ↓
Folder Content Encryption Keys (CEKs)
    ↓
File Content Encryption Keys (CEKs)
    ↓
File Data Encryption
```

### 2. User Key Derivation

#### Password-Based Key Derivation
```go
// PBKDF2 with HMAC-SHA512, 20000 iterations
derived := pbkdf2.Key([]byte(password), salt, 20000, 48, sha512.New)
aesKey := derived[:32]  // 32 bytes for AES-256
iv := derived[32:48]    // 16 bytes for IV
```

#### Private Key Decryption
The user's private key is encrypted with a custom PCTR (Parallel Counter) mode:
- Uses AES-256 in a custom counter mode
- Counter starts at 0, increments per 16-byte block
- Each counter block is XORed with IV before encryption

### 3. Folder Encryption Detection

Folders are detected as encrypted by checking the `encrypted` flag and presence of a `key` field in the folder metadata:

```go
// From listfolder API call
if !res.Metadata.Encrypted || res.Key == "" {
    // Plain folder
    return filename, nil
} else {
    // Encrypted folder - decrypt CEK and encrypt filename
}
```

### 4. Content Encryption Keys (CEKs)

#### Structure
```go
type FolderKey struct {
    Type    uint32  // Always 1
    Flags   uint32  // Always 0
    AESKey  []byte  // 32 bytes
    HMACKey []byte  // 32 bytes
}
```

#### Generation
Random keys generated using `crypto/rand`:
```go
aesKey := make([]byte, 32)
hmacKey := make([]byte, 32)
rand.Read(aesKey)
rand.Read(hmacKey)
```

#### Wrapping
CEKs are wrapped using RSA-OAEP with SHA-1:
```go
// Serialize: Type(4) + Flags(4) + AESKey(32) + HMACKey(32)
serialized := make([]byte, 72)
binary.LittleEndian.PutUint32(serialized[0:4], key.Type)
binary.LittleEndian.PutUint32(serialized[4:8], key.Flags)
copy(serialized[8:40], key.AESKey)
copy(serialized[40:72], key.HMACKey)

// Encrypt with user's public key
encryptedKey := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, serialized, nil)
```

### 5. File Encryption

#### Sector-Based Encryption
Files are divided into 4KB sectors, each encrypted independently with:
- **AES-256-CBC** for data encryption
- **HMAC-SHA512** for integrity verification
- **32-byte auth records** for each sector

#### Encryption Process
For each 4KB sector:
1. Generate random 16-byte nonce `o`
2. Compute `f = HMAC-SHA512(plaintext + sectorID + o)[:16]`
3. Build auth record: `n = o[:8] + f + o[8:]`
4. Encrypt auth: `auth = AES-ECB(n)`
5. Encrypt data using AES-CBC with IV=`f`

#### Special Handling for Short Sectors
Sectors smaller than 16 bytes use simple XOR with nonce prefix.

#### Tail Handling for Non-Multiple Sectors
For sectors not aligned to 16-byte boundaries, a complex tail construction ensures CBC integrity.

### 6. Authentication Tree

pCloud uses a hierarchical authentication tree (similar to a Merkle tree):

#### Tree Structure
```
Level 0: Per-sector auth records (32 bytes each)
Level 1: Auth records for groups of 128 sectors
Level 2: Auth records for groups of 128×128 sectors
...
Top Level: Master auth record
```

#### Auth Record Computation
Each auth record at level N is:
```
f = HMAC-SHA512(child_auth_records)[:32]
auth = AES-ECB(f)
```

### 7. Filename Encryption

#### Single Block (≤16 bytes)
```
xored = plaintext_filename XOR HMACKey[:16]
encrypted = AES-ECB(xored)
result = base32_encode(encrypted)
```

#### Multi-Block (>16 bytes)
```
iv = HMAC-SHA512(unpadded_tail)[:16]
encrypted = AES-CBC(plaintext_filename, iv)
result = base32_encode(encrypted)
```

### 8. Upload Process

#### Plain Files
1. Stream data directly to `upload_write` in chunks
2. Call `upload_save` with plain parameters

#### Encrypted Files
1. Generate random file CEK
2. Encrypt entire file content to pCloud Crypto format
3. Upload encrypted data in chunks to `upload_write`
4. Encrypt filename using folder CEK
5. Wrap file CEK with user's public key
6. Call `upload_save` with encrypted parameters

### 9. Download Process

#### Plain Files
1. Call `getfilelink` to get download URL
2. Stream download directly

#### Encrypted Files
1. Call `getfilelink` with `getkey=1` to get encrypted CEK
2. Decrypt file CEK using user's private key
3. Download encrypted file data
4. Decrypt file content using pCloud Crypto format
5. Verify integrity using auth tree

### 10. Sector Decryption

For each sector during decryption:
1. Decrypt auth record: `n = AES-ECB⁻¹(auth)`
2. Extract nonce `o` and MAC `f` from `n`
3. Decrypt data using AES-CBC with IV=`f`
4. Verify integrity: `HMAC-SHA512(decrypted_data + sectorID + o)[:16] == f`

### 11. Constants

```go
const (
    SectorSize  = 4096  // 4KB sectors
    AuthSize    = 32    // 32-byte auth records
    TreeSectors = 128   // 128 sectors per tree node
)
```

### 12. API Integration

#### Upload Endpoints
- `upload_create` - Initialize multi-part upload
- `upload_write` - Upload data chunks
- `upload_save` - Finalize upload with metadata

#### Download Endpoints
- `getfilelink` - Get download URL and encryption keys
- Direct HTTP download from CDN URLs

#### Folder Operations
- `listfolder` - Get folder contents and encryption status
- `createfolder` - Create new folders
- `renamefile/renamefolder` - Move/rename with encryption handling

### 13. Error Handling

Common encryption-related errors:
- `"crypto not initialized: no keyPair"` - Crypto password not provided
- `"sector auth compare fail"` - Data integrity verification failed
- `"decrypt folder key: ..."` - Invalid crypto password or corrupted keys

### 14. Compatibility

This implementation is fully compatible with:
- pCloud web interface encryption
- pCloud mobile apps
- pCloud desktop clients
- All pCloud Crypto format versions



// Add detailed logging for encrypted upload roundtrip test
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/StarHack/go-pcloud/pcloud"
)

// TestEncryptedRoundtrip tests uploading and downloading an encrypted file
// using the streaming API, verifying integrity via SHA-256 of the plaintext.
func TestEncryptedRoundtrip(t *testing.T) {
	email := os.Getenv("PCLOUD_EMAIL")
	password := os.Getenv("PCLOUD_PASSWORD")
	cryptoPassword := os.Getenv("PCLOUD_CRYPTO_PASSWORD")
	region := os.Getenv("PCLOUD_REGION")

	if email == "" || password == "" {
		t.Skip("Skipping test: PCLOUD_EMAIL and PCLOUD_PASSWORD must be set")
	}
	if cryptoPassword == "" {
		t.Skip("Skipping test: PCLOUD_CRYPTO_PASSWORD must be set for encrypted uploads")
	}
	if region == "" {
		region = "eu"
	}

	apiEndpoint := pcloud.EndpointAPI
	if strings.EqualFold(region, "eu") {
		apiEndpoint = pcloud.EndpointEAPI
	}

	c, err := pcloud.NewClient(email, password, cryptoPassword, apiEndpoint)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// List root dir to find crypto folder ID
	cryptoFolderID := int64(-1)
	entries, err := c.ListFolder(0)
	if err != nil {
		t.Fatalf("list folder failed: %v", err)
	}
	for _, e := range entries {
		if e.Encrypted {
			cryptoFolderID = int64(e.FolderID)
			break
		}
	}

	if cryptoFolderID == -1 {
		t.Fatalf("no encrypted folder found")
	}

	// Create an encrypted subdir for this test with a random name
	subdirName := fmt.Sprintf("test-encrypted-%d", time.Now().UnixNano())
	subdirMeta, err := c.CreateDirectory(cryptoFolderID, subdirName)
	if err != nil {
		t.Fatalf("create encrypted subdir failed: %v", err)
	}

	// Generate 5MB of random test data
	testData := make([]byte, 5*1024*1024)
	if _, err := io.ReadFull(rand.Reader, testData); err != nil {
		t.Fatalf("failed to generate test data: %v", err)
	}
	testReader := bytes.NewReader(testData)

	// Run the encrypted roundtrip test
	if err := streamEncryptedUploadThenDownload(c, int64(subdirMeta.FolderID), testReader, testData); err != nil {
		t.Fatalf("encrypted stream upload/download roundtrip failed: %v", err)
	}
}

// streamEncryptedUploadThenDownload uploads a local plaintext file to an encrypted
// folderID using the streaming encrypted upload API, then downloads it back using
// the encrypted streaming download API, and verifies integrity via SHA-256 of the
// decrypted plaintext content.
func streamEncryptedUploadThenDownload(c *pcloud.Client, folderID int64, dataReader io.Reader, originalData []byte) error {
	// Hash source plaintext
	sh := sha256.New()
	sh.Write(originalData)
	srcHash := hex.EncodeToString(sh.Sum(nil))

	// Reset reader for upload
	if seeker, ok := dataReader.(io.Seeker); ok {
		seeker.Seek(0, 0)
	}

	// Stream upload using encrypted writer (accepts plaintext, encrypts internally)
	name := "test-encrypted-random.dat"
	upStart := time.Now()
	w, err := c.UploadFileStream(folderID, name)
	if err != nil {
		return fmt.Errorf("create encrypted upload writer: %w", err)
	}

	written, err := io.Copy(w, dataReader)
	if err != nil {
		_ = w.Close()
		return fmt.Errorf("encrypted upload write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("encrypted upload close: %w", err)
	}

	meta := w.(interface{ Metadata() *pcloud.Metadata }).Metadata()
	if meta == nil {
		return fmt.Errorf("no metadata returned from encrypted upload")
	}
	fileID := int64(meta.FileID)
	upDur := time.Since(upStart)
	mb := float64(written) / (1024 * 1024)
	upMBps := mb / upDur.Seconds()
	fmt.Printf("encrypted upload completed: fileID=%d name=%s cipherSize=%d bytes plaintext=%d bytes duration=%s speed=%.2f MiB/s\n",
		fileID, name, meta.Size, written, upDur.Truncate(time.Millisecond), upMBps)

	// Stream download using encrypted reader (returns plaintext)
	dlStart := time.Now()
	rc, err := c.DownloadFileStream(fileID)
	if err != nil {
		return fmt.Errorf("encrypted stream download open: %w", err)
	}
	defer rc.Close()
	decH := sha256.New()
	dlBytes, err := io.Copy(decH, rc)
	if err != nil {
		return fmt.Errorf("encrypted stream download read: %w", err)
	}
	dlDur := time.Since(dlStart)
	dlMBps := (float64(dlBytes) / (1024 * 1024)) / dlDur.Seconds()
	decHash := hex.EncodeToString(decH.Sum(nil))
	match := srcHash == decHash
	fmt.Printf("encrypted download completed: plaintext=%d bytes duration=%s speed=%.2f MiB/s\n", dlBytes, dlDur.Truncate(time.Millisecond), dlMBps)
	fmt.Printf("encrypted stream round-trip verify: srcSHA256=%s dlSHA256=%s equal=%v\n", srcHash, decHash, match)
	if !match {
		return fmt.Errorf("mismatch: %s != %s", srcHash, decHash)
	}
	return nil
}

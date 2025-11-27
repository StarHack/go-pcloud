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

// TestPlaintextRoundtrip tests uploading and downloading a plaintext file
// using the streaming API, verifying integrity via SHA-256.
func TestPlaintextRoundtrip(t *testing.T) {
	// Read credentials from environment
	email := os.Getenv("PCLOUD_EMAIL")
	password := os.Getenv("PCLOUD_PASSWORD")
	region := os.Getenv("PCLOUD_REGION")
	targetFolder := os.Getenv("PCLOUD_PLAIN_TARGET_DIR")

	if email == "" || password == "" {
		t.Skip("Skipping test: PCLOUD_EMAIL and PCLOUD_PASSWORD must be set")
	}
	if region == "" {
		region = "eu"
	}

	apiEndpoint := pcloud.EndpointAPI
	if strings.EqualFold(region, "eu") {
		apiEndpoint = pcloud.EndpointEAPI
	}

	c, err := pcloud.NewClient(email, password, "", apiEndpoint)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Generate 5MB of random test data
	testData := make([]byte, 5*1024*1024)
	if _, err := io.ReadFull(rand.Reader, testData); err != nil {
		t.Fatalf("failed to generate test data: %v", err)
	}
	testReader := bytes.NewReader(testData)

	// Use target folder from environment, default to root (0)
	folderID := int64(0)
	if targetFolder != "" {
		var parsed int64
		if _, err := fmt.Sscanf(targetFolder, "%d", &parsed); err == nil {
			folderID = parsed
		} else {
			t.Logf("Warning: invalid PCLOUD_PLAIN_TARGET_DIR '%s', using root folder", targetFolder)
		}
	}

	// Run the roundtrip test
	if err := streamUploadThenDownload(c, folderID, testReader, testData); err != nil {
		// If the error is about crypto not initialized, it means the folder is encrypted
		if strings.Contains(err.Error(), "crypto not initialized") {
			t.Skipf("Skipping plain test: target folder %d appears to be encrypted but crypto is not initialized: %s", folderID, err.Error())
		}
		t.Fatalf("stream upload/download roundtrip failed: %v", err)
	}
}

// streamUploadThenDownload uploads a small local plaintext file to folderID using
// the streaming upload API, then downloads it back using the streaming download API,
// and verifies integrity via SHA-256.
func streamUploadThenDownload(c *pcloud.Client, folderID int64, dataReader io.Reader, originalData []byte) error {
	// Hash source
	sh := sha256.New()
	sh.Write(originalData)
	srcHash := hex.EncodeToString(sh.Sum(nil))

	// Reset reader for upload
	if seeker, ok := dataReader.(io.Seeker); ok {
		seeker.Seek(0, 0)
	}

	// Stream upload using multi-step unknown-size writer
	name := "test-plain-random.dat"
	upStart := time.Now()
	w, err := c.UploadFileStream(folderID, name)
	if err != nil {
		return fmt.Errorf("create unknown-size upload writer: %w", err)
	}
	written, err := io.Copy(w, dataReader)
	if err != nil {
		_ = w.Close()
		return fmt.Errorf("upload write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("upload close: %w", err)
	}
	meta := w.(interface{ Metadata() *pcloud.Entry }).Metadata()
	if meta == nil {
		return fmt.Errorf("no metadata returned from multi-step upload")
	}
	fileID := int64(meta.FileID)
	upDur := time.Since(upStart)
	upBytes := int64(meta.Size)
	// Trust metadata size if it differs from bytes written (it may if source changed mid-stream)
	uEffective := upBytes
	mb := float64(uEffective) / (1024 * 1024)
	upMBps := mb / upDur.Seconds()
	fmt.Printf("upload completed: fileID=%d name=%s size=%d bytes duration=%s speed=%.2f MiB/s (written=%d)\n", fileID, name, meta.Size, upDur.Truncate(time.Millisecond), upMBps, written)

	// Stream download using new StreamFileReader
	dlStart := time.Now()
	rc, err := c.DownloadFileStream(fileID)
	if err != nil {
		return fmt.Errorf("stream download open: %w", err)
	}
	defer rc.Close()
	decH := sha256.New()
	if _, err := io.Copy(decH, rc); err != nil {
		return fmt.Errorf("stream download read: %w", err)
	}
	dlDur := time.Since(dlStart)
	dlBytes := upBytes // expected same size
	dlMBps := (float64(dlBytes) / (1024 * 1024)) / dlDur.Seconds()
	decHash := hex.EncodeToString(decH.Sum(nil))
	match := srcHash == decHash
	fmt.Printf("download completed: size=%d bytes duration=%s speed=%.2f MiB/s\n", dlBytes, dlDur.Truncate(time.Millisecond), dlMBps)
	fmt.Printf("stream round-trip verify: srcSHA256=%s dlSHA256=%s equal=%v\n", srcHash, decHash, match)
	if !match {
		return fmt.Errorf("mismatch: %s != %s", srcHash, decHash)
	}
	return nil
}

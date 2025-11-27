package pcloud

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// UploadFileStream returns an io.WriteCloser that performs multi-step
// upload_create / upload_write / upload_save without requiring the final size.
// It automatically detects if the folder is encrypted and encrypts the data if needed.
// For plain folders, data is buffered in 16MB chunks and flushed incrementally.
// For encrypted folders, data is buffered entirely, encrypted on Close(), and uploaded in chunks.
func (c *Client) UploadFileStream(folderID int64, filename string) (io.WriteCloser, error) {
	// Check if folder is encrypted by trying to encrypt the filename
	encName, err := c.EncryptFilenameForFolder(folderID, filename)
	if err != nil {
		return nil, fmt.Errorf("check folder encryption: %w", err)
	}
	isEncrypted := encName != filename

	uploadID, err := c.encryptedUploadCreate()
	if err != nil {
		return nil, fmt.Errorf("upload_create: %w", err)
	}

	if isEncrypted {
		if c.keyPair == nil {
			return nil, fmt.Errorf("crypto not initialized: missing keyPair (set CryptoPassword)")
		}
		// Generate file key
		fk, err := c.keyPair.GenerateFileKey()
		if err != nil {
			return nil, fmt.Errorf("generate file key: %w", err)
		}
		encCEK, err := c.keyPair.EncryptFolderKey(*fk)
		if err != nil {
			return nil, fmt.Errorf("encrypt CEK: %w", err)
		}
		w := &unifiedStreamWriter{
			c:           c,
			folderID:    folderID,
			name:        encName,
			uploadID:    uploadID,
			buf:         make([]byte, 0, 16<<20), // 16MB
			isEncrypted: true,
			fileKey:     *fk,
			encCEK:      encCEK,
			mtime:       time.Now(),
		}
		return w, nil
	} else {
		w := &unifiedStreamWriter{
			c:           c,
			folderID:    folderID,
			name:        filename,
			uploadID:    uploadID,
			buf:         make([]byte, 0, 16<<20), // 16MB
			isEncrypted: false,
			mtime:       time.Now(),
		}
		return w, nil
	}
}

type unifiedStreamWriter struct {
	c           *Client
	folderID    int64
	name        string
	uploadID    int64
	buf         []byte
	offset      int64
	closed      bool
	meta        *Entry
	err         error
	mtime       time.Time
	isEncrypted bool
	fileKey     FolderKey
	encCEK      string
}

func (w *unifiedStreamWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, fmt.Errorf("writer closed")
	}
	if w.isEncrypted {
		// For encrypted uploads, buffer all data since encryption requires the complete file
		total := 0
		for len(p) > 0 {
			space := cap(w.buf) - len(w.buf)
			if space == 0 {
				// Grow buffer
				newBuf := make([]byte, len(w.buf), cap(w.buf)*2)
				copy(newBuf, w.buf)
				w.buf = newBuf
				space = cap(w.buf) - len(w.buf)
			}
			n := space
			if n > len(p) {
				n = len(p)
			}
			w.buf = append(w.buf, p[:n]...)
			p = p[n:]
			total += n
		}
		return total, nil
	} else {
		// Plain uploads: buffer in chunks and flush incrementally
		total := 0
		for len(p) > 0 {
			space := cap(w.buf) - len(w.buf)
			if space == 0 {
				if err := w.flush(); err != nil {
					return total, err
				}
				space = cap(w.buf) - len(w.buf)
			}
			n := space
			if n > len(p) {
				n = len(p)
			}
			w.buf = append(w.buf, p[:n]...)
			p = p[n:]
			total += n
			if len(w.buf) == cap(w.buf) {
				if err := w.flush(); err != nil {
					return total, err
				}
			}
		}
		return total, nil
	}
}

func (w *unifiedStreamWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	r := bytes.NewReader(w.buf)
	size := int64(len(w.buf))
	u := w.c.Endpoint + "upload_write"
	q := url.Values{}
	if w.c.AuthToken != "" {
		q.Set("auth", w.c.AuthToken)
	} else if w.c.AccessToken != "" {
		q.Set("access_token", w.c.AccessToken)
	}
	q.Set("uploadid", fmt.Sprintf("%d", w.uploadID))
	q.Set("uploadoffset", fmt.Sprintf("%d", w.offset))
	q.Set("uploadsize", fmt.Sprintf("%d", size))
	u += "?" + q.Encode()
	req, err := http.NewRequest(http.MethodPut, u, r)
	if err != nil {
		return err
	}
	req.ContentLength = size
	resp, err := w.c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload_write HTTP %d: %s", resp.StatusCode, string(b))
	}
	w.offset += size
	w.buf = w.buf[:0]
	return nil
}

func (w *unifiedStreamWriter) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.isEncrypted {
		// Encrypt all buffered plain data
		cipherBuf, err := EncryptFileContentsFromPlain(w.buf, w.fileKey)
		if err != nil {
			w.err = fmt.Errorf("encrypt file contents: %w", err)
			return w.err
		}

		// Upload the encrypted data in chunks to enable streaming upload
		const chunkSize = 16 << 20 // 16MB chunks
		totalSize := int64(len(cipherBuf))
		offset := int64(0)
		for offset < totalSize {
			remaining := totalSize - offset
			if remaining > chunkSize {
				remaining = chunkSize
			}
			r := bytes.NewReader(cipherBuf[offset : offset+remaining])
			if err := w.c.encryptedUploadWrite(w.uploadID, offset, r, remaining); err != nil {
				w.err = err
				return err
			}
			offset += remaining
		}

		meta, err := w.c.encryptedUploadSave(w.uploadID, w.folderID, w.name, true, w.encCEK, w.mtime)
		if err != nil {
			w.err = err
			return err
		}
		w.meta = meta
	} else {
		// Plain upload: flush remaining buffer and save
		if err := w.flush(); err != nil {
			w.err = err
			return err
		}
		params := map[string]any{
			"uploadid": w.uploadID,
			"folderid": w.folderID,
			"name":     w.name,
			"mtime":    w.mtime.Unix(),
		}
		r, err := w.c.call("upload_save", true, true, "", params)
		if err != nil {
			w.err = err
			return err
		}
		m, ok := r.(map[string]any)
		if !ok {
			w.err = fmt.Errorf("unexpected upload_save response type")
			return w.err
		}
		if res, ok := m["result"].(float64); ok && res != 0 {
			errMsg, _ := m["error"].(string)
			if errMsg == "" {
				errMsg = "upload_save error"
			}
			w.err = fmt.Errorf("%s", errMsg)
			return w.err
		}
		if md, ok := m["metadata"].(map[string]any); ok {
			j, _ := jsonMarshalNoEscape(md)
			var meta Entry
			if jsonUnmarshalNumbers(j, &meta) == nil {
				w.meta = &meta
			}
		}
	}
	return nil
}

func (w *unifiedStreamWriter) Metadata() *Entry { return w.meta }

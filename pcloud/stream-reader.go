package pcloud

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
)

// getFileLinkRaw calls getfilelink API and returns the parsed response.
func (c *Client) getFileLinkRaw(fileid int64, getKey bool) (*GetFileLinkResponse, error) {
	params := map[string]any{"fileid": fileid}
	if getKey {
		params["getkey"] = 1
	}

	r, err := c.call("getfilelink", true, true, "", params)
	if err != nil {
		return nil, err
	}

	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected getfilelink response")
	}

	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}

	var resp GetFileLinkResponse
	if err := jsonUnmarshalNumbers(j, &resp); err != nil {
		return nil, err
	}

	if resp.Result != 0 {
		return nil, fmt.Errorf("getfilelink error: %s", resp.Error)
	}

	return &resp, nil
}

// DownloadFileStream downloads and decrypts an encrypted file if needed.
// It returns an io.ReadCloser that streams the decrypted plaintext.
// If the file is not encrypted or crypto keys are not available, it returns the raw file data.
func (c *Client) DownloadFileStream(fileid int64) (io.ReadCloser, error) {
	// Get file link with key if we have crypto capabilities
	getKey := c.keyPair != nil
	resp, err := c.getFileLinkRaw(fileid, getKey)
	if err != nil {
		return nil, err
	}

	if len(resp.Hosts) == 0 || resp.Path == "" {
		return nil, fmt.Errorf("getfilelink missing hosts or path")
	}

	// Build the download URL directly from API path to avoid double encoding
	base := "https://" + resp.Hosts[0] + resp.Path
	qs, _ := url.Parse(base)
	q := qs.Query()
	if c.AuthToken != "" && q.Get("auth") == "" {
		q.Set("auth", c.AuthToken)
	}
	if c.AccessToken != "" && q.Get("access_token") == "" {
		q.Set("access_token", c.AccessToken)
	}
	qs.RawQuery = q.Encode()

	// Download the file
	httpResp, err := c.http.Get(qs.String())
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	rc := httpResp.Body
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	// If file is encrypted and we have the key, decrypt it
	if resp.Key != "" && c.keyPair != nil {
		fileKey, err := c.keyPair.DecryptFolderKey(resp.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt file key: %w", err)
		}

		decrypted, err := DecryptFileContents(data, *fileKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt file contents (size=%d, expected_size=%d): %w",
				len(data), resp.Size, err)
		}

		return io.NopCloser(bytes.NewReader(decrypted)), nil
	}

	// Return raw data if not encrypted
	return io.NopCloser(bytes.NewReader(data)), nil
}

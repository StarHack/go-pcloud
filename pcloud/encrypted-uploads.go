package pcloud

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// UploadCreateResponse is the JSON returned by upload_create
type UploadCreateResponse struct {
	Result   int    `json:"result"`
	Error    string `json:"error,omitempty"`
	UploadID int64  `json:"uploadid"`
}

// UploadSaveResponse represents the minimal useful part of upload_save
type UploadSaveResponse struct {
	Result   int       `json:"result"`
	Error    string    `json:"error,omitempty"`
	Metadata *Metadata `json:"metadata,omitempty"`
}

// encryptedUploadCreate starts a multi-step upload and returns uploadid.
// It calls the eapi upload_create endpoint using the client's configured endpoint.
func (c *Client) encryptedUploadCreate() (int64, error) {
	r, err := c.call("upload_create", true, true, "", nil)
	if err != nil {
		return 0, err
	}
	m, ok := r.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("unexpected upload_create response")
	}
	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return 0, err
	}
	var out UploadCreateResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return 0, err
	}
	if out.Result != 0 {
		if out.Error == "" {
			out.Error = "unknown error"
		}
		return 0, fmt.Errorf("upload_create: %s", out.Error)
	}
	return out.UploadID, nil
}

// encryptedUploadWrite writes a chunk of the (already encrypted) data to the server.
// size must be provided and will be sent as the uploadsize parameter.
func (c *Client) encryptedUploadWrite(uploadID int64, offset int64, r io.Reader, size int64) error {
	// Build URL with query params
	u := c.Endpoint + "upload_write"
	q := url.Values{}
	if c.AuthToken != "" {
		q.Set("auth", c.AuthToken)
	} else if c.AccessToken != "" {
		q.Set("access_token", c.AccessToken)
	}
	q.Set("uploadid", fmt.Sprintf("%d", uploadID))
	q.Set("uploadoffset", fmt.Sprintf("%d", offset))
	q.Set("uploadsize", fmt.Sprintf("%d", size))
	u += "?" + q.Encode()

	req, err := http.NewRequest(http.MethodPut, u, r)
	if err != nil {
		return err
	}
	req.ContentLength = size
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload_write HTTP %d: %s", resp.StatusCode, string(b))
	}
	// Some servers return empty body; treat non-200 as errors only
	return nil
}

// encryptedUploadSave finalizes the upload. The name should already be encrypted (Base32) when encrypted=1.
// key must be the base64url-encoded RSA-OAEP encrypted file key (CEK). mtime is file modification time.
func (c *Client) encryptedUploadSave(uploadID, folderID int64, name string, encrypted bool, key string, mtime time.Time) (*Metadata, error) {
	params := map[string]any{
		"uploadid": uploadID,
		"folderid": folderID,
		"name":     name,
		"mtime":    mtime.Unix(),
	}
	if encrypted {
		params["encrypted"] = 1
		params["key"] = key
	}
	r, err := c.call("upload_save", true, true, "", params)
	if err != nil {
		return nil, err
	}
	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected upload_save response")
	}
	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}
	var out UploadSaveResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}
	if out.Result != 0 {
		if out.Error == "" {
			out.Error = "unknown error"
		}
		return nil, fmt.Errorf("upload_save: %s", out.Error)
	}
	return out.Metadata, nil
}

// EncryptFilenameForFolder returns the encrypted filename using the folder's CEK.
// For non-encrypted folders, returns the name unchanged.
// For encrypted folders, requires the client to have a decrypted keyPair (CryptoPassword provided).
func (c *Client) EncryptFilenameForFolder(folderID int64, name string) (string, error) {
	// Get folder's encrypted key by listing the folder with getkey (only if we have keys)
	res, err := c.listFolderRaw(folderID)
	if err != nil {
		return "", err
	}
	if res.Result != 0 {
		return "", fmt.Errorf("listfolder error: %s", res.Error)
	}
	if !res.Metadata.Encrypted || res.Key == "" {
		// Non-encrypted folder: name is used as-is
		return name, nil
	}
	// Encrypted folder: need crypto keys
	if c.keyPair == nil {
		return "", fmt.Errorf("crypto not initialized: no keyPair")
	}
	fKey, err := c.keyPair.DecryptFolderKey(res.Key)
	if err != nil {
		return "", fmt.Errorf("decrypt folder key: %w", err)
	}
	enc, err := EncryptFilename(name, *fKey)
	if err != nil {
		return "", err
	}
	return enc, nil
}

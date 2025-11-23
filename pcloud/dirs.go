package pcloud

import (
	"errors"
	"fmt"
)

func (c *Client) listFolderRaw(folderID int64) (*ListFolderResponse, error) {
	params := map[string]any{"folderid": folderID}
	// If we have crypto keys, request the encrypted folder keys
	if c.keyPair != nil {
		params["getkey"] = 1
	}
	r, err := c.call("listfolder", true, true, "", params)
	if err != nil {
		return nil, err
	}
	b, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response")
	}
	j, err := jsonMarshalNoEscape(b)
	if err != nil {
		return nil, err
	}
	var out ListFolderResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}
	if out.Result != 0 {
		return &out, fmt.Errorf("api error: %s", out.Error)
	}
	return &out, nil
}

func (c *Client) ListFolder(folderID int64) ([]Entry, error) {
	res, err := c.listFolderRaw(folderID)
	if err != nil {
		return nil, err
	}

	// Decrypt entries if they are encrypted and we have the keys
	// The ListFolderResponse contains the key needed to decrypt its contents
	if c.keyPair != nil && res.Metadata.Encrypted && res.Key != "" {
		// Decrypt the folder key (CEK) from the response
		folderKey, err := c.keyPair.DecryptFolderKey(res.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt folder key: %w", err)
		}

		// Decrypt each encrypted entry's name using the folder's key
		for i, it := range res.Metadata.Contents {
			if it.Encrypted {
				// Decrypt the filename
				decryptedName, err := DecryptFilename(it.Name, *folderKey)
				if err != nil {
					fmt.Printf("Warning: failed to decrypt filename %s: %v\n", it.Name, err)
					continue
				}

				// Update the entry with the decrypted name
				res.Metadata.Contents[i].Name = decryptedName
			}
		}
	}

	return res.Metadata.Contents, nil
}

// CreateDirectory creates a new folder under parentFolderID with the given name.
// Returns the folder metadata on success.
// For known API error codes, returns a typed sentinel error (e.g., ErrFolderAlreadyExists).
func (c *Client) CreateDirectory(parentFolderID int64, name string) (*Metadata, error) {
	r, err := c.call("createfolder", true, true, "", map[string]any{
		"folderid": parentFolderID,
		"name":     name,
	})
	if err != nil {
		return nil, err
	}

	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response")
	}

	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}

	var out CreateFolderResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}

	if out.Result != 0 {
		switch out.Result {
		case 2004:
			return nil, ErrFolderAlreadyExists
		case 2001:
			return nil, ErrFileNotFound
		case 1000:
			return nil, ErrInvalidAuth
		default:
			msg := out.Error
			if msg == "" {
				msg = "unknown error"
			}
			return nil, errors.New(msg)
		}
	}

	if out.Metadata == nil {
		return nil, fmt.Errorf("missing metadata in response")
	}

	return out.Metadata, nil
}

func (c *Client) Rename(entry Entry, toName string) (*Metadata, error) {
	if entry.IsFolder {
		return c.renameFolder(int64(entry.FolderID), toName)
	}
	return c.renameFile(int64(entry.FileID), toName)
}

func (c *Client) renameFile(fileID int64, toName string) (*Metadata, error) {
	r, err := c.call("renamefile", true, true, "", map[string]any{
		"fileid": fileID,
		"toname": toName,
	})
	if err != nil {
		return nil, err
	}
	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response")
	}
	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}
	var out RenameResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}
	if err := apiErr(out.Result, out.Error); err != nil {
		return nil, err
	}
	if out.Metadata == nil {
		return nil, fmt.Errorf("missing metadata in response")
	}
	return out.Metadata, nil
}

func (c *Client) Delete(entry Entry, toName string) error {
	if entry.IsFolder {
		_, err := c.DeleteFolderRecursive(int64(entry.FolderID), toName)
		return err
	}
	_, err := c.DeleteFile(int64(entry.FileID), toName)
	return err
}

func (c *Client) DeleteFile(fileID int64, reqID string) (*DeleteFileResponse, error) {
	params := map[string]any{"fileid": fileID}
	if reqID != "" {
		params["id"] = reqID
	}
	r, err := c.call("deletefile", true, true, "", params)
	if err != nil {
		return nil, err
	}
	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response")
	}
	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}
	var out DeleteFileResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}
	if err := apiErr(out.Result, out.Error); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) renameFolder(folderID int64, toName string) (*Metadata, error) {
	r, err := c.call("renamefolder", true, true, "", map[string]any{
		"folderid": folderID,
		"toname":   toName,
	})
	if err != nil {
		return nil, err
	}
	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response")
	}
	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}
	var out RenameResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}
	if err := apiErr(out.Result, out.Error); err != nil {
		return nil, err
	}
	if out.Metadata == nil {
		return nil, fmt.Errorf("missing metadata in response")
	}
	return out.Metadata, nil
}

func (c *Client) DeleteFolderRecursive(folderID int64, reqID string) (*DeleteFolderRecursiveResponse, error) {
	params := map[string]any{"folderid": folderID}
	if reqID != "" {
		params["id"] = reqID
	}
	r, err := c.call("deletefolderrecursive", true, true, "", params)
	if err != nil {
		return nil, err
	}
	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response")
	}
	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}
	var out DeleteFolderRecursiveResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}
	if err := apiErr(out.Result, out.Error); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteItem deletes an item using info from an Entry.
// For folders it performs a recursive delete; for files it deletes the file.
func (c *Client) DeleteItemByEntry(e Entry) error {
	if e.IsFolder {
		_, err := c.DeleteFolderRecursive(int64(e.FolderID), "")
		return err
	}
	_, err := c.DeleteFile(int64(e.FileID), "")
	return err
}

// Move moves a file or folder to a different folder, retaining the original name.
// Prevents overwriting existing items (noover=1).
func (c *Client) Move(entry Entry, toFolderID int64) (*Metadata, error) {
	if entry.IsFolder {
		return c.moveFolder(int64(entry.FolderID), toFolderID, entry.Name, true)
	}
	return c.moveFile(int64(entry.FileID), toFolderID, entry.Name, true)
}

// moveFile moves a file to a different folder with a new name.
// Prevents overwriting existing items (noover=1).
func (c *Client) moveFile(fileID int64, toFolderID int64, toName string, noover bool) (*Metadata, error) {
	params := map[string]any{
		"fileid":     fileID,
		"tofolderid": toFolderID,
		"toname":     toName,
		"noover":     1,
	}
	r, err := c.call("renamefile", true, true, "", params)
	if err != nil {
		return nil, err
	}
	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response")
	}
	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}
	var out RenameResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}
	if err := apiErr(out.Result, out.Error); err != nil {
		return nil, err
	}
	if out.Metadata == nil {
		return nil, fmt.Errorf("missing metadata in response")
	}
	return out.Metadata, nil
}

// moveFolder moves a folder to a different parent folder with a new name.
// Prevents overwriting existing items (noover=1).
func (c *Client) moveFolder(folderID int64, toFolderID int64, toName string, noover bool) (*Metadata, error) {
	params := map[string]any{
		"folderid":   folderID,
		"tofolderid": toFolderID,
		"toname":     toName,
		"noover":     1,
	}
	r, err := c.call("renamefolder", true, true, "", params)
	if err != nil {
		return nil, err
	}
	m, ok := r.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response")
	}
	j, err := jsonMarshalNoEscape(m)
	if err != nil {
		return nil, err
	}
	var out RenameResponse
	if err := jsonUnmarshalNumbers(j, &out); err != nil {
		return nil, err
	}
	if err := apiErr(out.Result, out.Error); err != nil {
		return nil, err
	}
	if out.Metadata == nil {
		return nil, fmt.Errorf("missing metadata in response")
	}
	return out.Metadata, nil
}

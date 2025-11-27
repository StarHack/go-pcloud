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
func (c *Client) CreateDirectory(parentFolderID int64, name string) (*Entry, error) {
	// Check if parent folder is encrypted
	parentInfo, err := c.listFolderRaw(parentFolderID)
	if err != nil {
		return nil, fmt.Errorf("failed to check parent folder: %w", err)
	}
	if parentInfo.Result != 0 {
		return nil, fmt.Errorf("parent folder error: %s", parentInfo.Error)
	}

	params := map[string]any{
		"folderid": parentFolderID,
		"name":     name,
	}

	// If parent is encrypted, we need to encrypt the folder name and generate a key
	if parentInfo.Metadata.Encrypted && parentInfo.Key != "" {
		if c.keyPair == nil {
			return nil, fmt.Errorf("crypto not initialized: cannot create folder in encrypted directory")
		}

		// Decrypt parent folder's CEK
		parentKey, err := c.keyPair.DecryptFolderKey(parentInfo.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt parent folder key: %w", err)
		}

		// Encrypt the folder name using parent's CEK
		encryptedName, err := EncryptFilename(name, *parentKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt folder name: %w", err)
		}
		params["name"] = encryptedName

		// Generate a new CEK for the new folder
		newFolderKey, err := c.keyPair.GenerateFileKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate folder key: %w", err)
		}

		// Encrypt the new CEK with user's public key
		encryptedKey, err := c.keyPair.EncryptFolderKey(*newFolderKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt folder key: %w", err)
		}

		params["encrypted"] = 1
		params["key"] = encryptedKey
	}

	r, err := c.call("createfolder", true, true, "", params)
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

func (c *Client) Rename(entry Entry, toName string) (*Entry, error) {
	if entry.IsFolder {
		return c.renameFolder(int64(entry.FolderID), toName)
	}
	return c.renameFile(int64(entry.FileID), toName)
}

func (c *Client) renameFile(fileID int64, toName string) (*Entry, error) {
	// For rename operations, we need to encrypt the new name if the file's parent folder is encrypted
	fileInfo, err := c.StatByFileID(fileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}
	parentID := fileInfo["parentfolderid"].(float64)

	// Check if parent folder is encrypted
	parentInfo, err := c.listFolderRaw(int64(parentID))
	if err != nil {
		return nil, fmt.Errorf("failed to check parent folder: %w", err)
	}
	if parentInfo.Result != 0 {
		return nil, fmt.Errorf("parent folder error: %s", parentInfo.Error)
	}

	params := map[string]any{
		"fileid": fileID,
		"toname": toName,
	}

	// If parent is encrypted, encrypt the new filename
	if parentInfo.Metadata.Encrypted && parentInfo.Key != "" {
		if c.keyPair == nil {
			return nil, fmt.Errorf("crypto not initialized: cannot rename file in encrypted directory")
		}

		// Decrypt parent folder's CEK
		parentKey, err := c.keyPair.DecryptFolderKey(parentInfo.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt parent folder key: %w", err)
		}

		// Encrypt the new filename using parent's CEK
		encryptedName, err := EncryptFilename(toName, *parentKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt filename: %w", err)
		}
		params["toname"] = encryptedName
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

func (c *Client) Delete(entry Entry) error {
	if entry.IsFolder {
		_, err := c.DeleteFolderRecursive(int64(entry.FolderID), "")
		return err
	}
	_, err := c.DeleteFile(int64(entry.FileID), "")
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

func (c *Client) renameFolder(folderID int64, toName string) (*Entry, error) {
	// For rename operations, we need to encrypt the new name if the folder's parent is encrypted
	folderInfo, err := c.StatByFileID(folderID)
	if err != nil {
		return nil, fmt.Errorf("failed to get folder info: %w", err)
	}
	parentID := folderInfo["parentfolderid"].(float64)

	// Check if parent folder is encrypted
	parentInfo, err := c.listFolderRaw(int64(parentID))
	if err != nil {
		return nil, fmt.Errorf("failed to check parent folder: %w", err)
	}
	if parentInfo.Result != 0 {
		return nil, fmt.Errorf("parent folder error: %s", parentInfo.Error)
	}

	params := map[string]any{
		"folderid": folderID,
		"toname":   toName,
	}

	// If parent is encrypted, encrypt the new folder name
	if parentInfo.Metadata.Encrypted && parentInfo.Key != "" {
		if c.keyPair == nil {
			return nil, fmt.Errorf("crypto not initialized: cannot rename folder in encrypted directory")
		}

		// Decrypt parent folder's CEK
		parentKey, err := c.keyPair.DecryptFolderKey(parentInfo.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt parent folder key: %w", err)
		}

		// Encrypt the new folder name using parent's CEK
		encryptedName, err := EncryptFilename(toName, *parentKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt folder name: %w", err)
		}
		params["toname"] = encryptedName
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
func (c *Client) Move(entry Entry, toFolderID int64) (*Entry, error) {
	if entry.IsFolder {
		return c.moveFolder(int64(entry.FolderID), toFolderID, entry.Name, true)
	}
	return c.moveFile(int64(entry.FileID), toFolderID, entry.Name, true)
}

// moveFile moves a file to a different folder with a new name.
// Prevents overwriting existing items (noover=1).
func (c *Client) moveFile(fileID int64, toFolderID int64, toName string, noover bool) (*Entry, error) {
	// Check if destination folder is encrypted
	destInfo, err := c.listFolderRaw(toFolderID)
	if err != nil {
		return nil, fmt.Errorf("failed to check destination folder: %w", err)
	}
	if destInfo.Result != 0 {
		return nil, fmt.Errorf("destination folder error: %s", destInfo.Error)
	}

	params := map[string]any{
		"fileid":     fileID,
		"tofolderid": toFolderID,
		"toname":     toName,
		"noover":     1,
	}

	// If destination is encrypted, encrypt the filename
	if destInfo.Metadata.Encrypted && destInfo.Key != "" {
		if c.keyPair == nil {
			return nil, fmt.Errorf("crypto not initialized: cannot move file to encrypted directory")
		}

		// Decrypt destination folder's CEK
		destKey, err := c.keyPair.DecryptFolderKey(destInfo.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt destination folder key: %w", err)
		}

		// Encrypt the filename using destination's CEK
		encryptedName, err := EncryptFilename(toName, *destKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt filename: %w", err)
		}
		params["toname"] = encryptedName
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
func (c *Client) moveFolder(folderID int64, toFolderID int64, toName string, noover bool) (*Entry, error) {
	// Check if destination folder is encrypted
	destInfo, err := c.listFolderRaw(toFolderID)
	if err != nil {
		return nil, fmt.Errorf("failed to check destination folder: %w", err)
	}
	if destInfo.Result != 0 {
		return nil, fmt.Errorf("destination folder error: %s", destInfo.Error)
	}

	params := map[string]any{
		"folderid":   folderID,
		"tofolderid": toFolderID,
		"toname":     toName,
		"noover":     1,
	}

	// If destination is encrypted, encrypt the folder name
	if destInfo.Metadata.Encrypted && destInfo.Key != "" {
		if c.keyPair == nil {
			return nil, fmt.Errorf("crypto not initialized: cannot move folder to encrypted directory")
		}

		// Decrypt destination folder's CEK
		destKey, err := c.keyPair.DecryptFolderKey(destInfo.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt destination folder key: %w", err)
		}

		// Encrypt the folder name using destination's CEK
		encryptedName, err := EncryptFilename(toName, *destKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt folder name: %w", err)
		}
		params["toname"] = encryptedName
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

package pcloud

import (
	"errors"
	"time"
)

var (
	ErrFolderAlreadyExists = errors.New("folder already exists")
	ErrFileNotFound        = errors.New("file or folder not found")
	ErrInvalidAuth         = errors.New("invalid authentication")
)

type RFC1123Time struct{ time.Time }
type Int64Number int64

type ListFolderResponse struct {
	Result   int      `json:"result"`
	Error    string   `json:"error,omitempty"`
	Metadata Metadata `json:"metadata"`
	Key      string   `json:"key,omitempty"` // Encrypted folder key (CEK) from API when getkey=1
	Auth     string   `json:"auth,omitempty"`
	Checks   any      `json:"checks,omitempty"`
	Params   any      `json:"params,omitempty"`
	Request  string   `json:"request,omitempty"`
}

type Metadata struct {
	ID             string        `json:"id"`
	FolderID       Int64Number   `json:"folderid"`
	FileID         Int64Number   `json:"fileid,omitempty"`
	ParentFolderID Int64Number   `json:"parentfolderid,omitempty"`
	Name           string        `json:"name"`
	Path           string        `json:"path"`
	Icon           string        `json:"icon"`
	IsFolder       bool          `json:"isfolder"`
	IsMine         bool          `json:"ismine"`
	IsShared       bool          `json:"isshared"`
	IsPublic       bool          `json:"ispublic,omitempty"`
	IsPublicRoot   bool          `json:"ispublicroot,omitempty"`
	Encrypted      bool          `json:"encrypted,omitempty"`
	Thumb          bool          `json:"thumb"`
	ContentType    string        `json:"contenttype,omitempty"`
	Category       int           `json:"category,omitempty"`
	Size           Int64Number   `json:"size,omitempty"`
	Hash           NumericString `json:"hash,omitempty"`
	Comments       int           `json:"comments"`
	Created        RFC1123Time   `json:"created"`
	Modified       RFC1123Time   `json:"modified"`
	Contents       []Entry       `json:"contents,omitempty"`
}

type Entry struct {
	ID             string        `json:"id"`
	IsFolder       bool          `json:"isfolder"`
	Name           string        `json:"name"`
	Path           string        `json:"path"`
	Icon           string        `json:"icon"`
	Thumb          bool          `json:"thumb"`
	IsMine         bool          `json:"ismine"`
	IsShared       bool          `json:"isshared"`
	IsPublic       bool          `json:"ispublic,omitempty"`
	IsPublicRoot   bool          `json:"ispublicroot,omitempty"`
	Encrypted      bool          `json:"encrypted,omitempty"`
	Comments       int           `json:"comments"`
	Created        RFC1123Time   `json:"created"`
	Modified       RFC1123Time   `json:"modified"`
	FolderID       Int64Number   `json:"folderid,omitempty"`
	ParentFolderID Int64Number   `json:"parentfolderid,omitempty"`
	FileID         Int64Number   `json:"fileid,omitempty"`
	Size           Int64Number   `json:"size,omitempty"`
	ContentType    string        `json:"contenttype,omitempty"`
	Category       int           `json:"category,omitempty"`
	Hash           NumericString `json:"hash,omitempty"`
	Key            string        `json:"key,omitempty"` // Encrypted folder key (CEK) from API when getkey=1
}

type CreateFolderResponse struct {
	Result   int       `json:"result"`
	Error    string    `json:"error,omitempty"`
	Metadata *Metadata `json:"metadata,omitempty"`
}

type RenameResponse struct {
	Result   int       `json:"result"`
	Error    string    `json:"error,omitempty"`
	Metadata *Metadata `json:"metadata,omitempty"`
}

type DeleteFileResponse struct {
	Result   int       `json:"result"`
	Error    string    `json:"error,omitempty"`
	ID       string    `json:"id,omitempty"`
	Metadata *Metadata `json:"metadata,omitempty"`
}

type DeleteFolderRecursiveResponse struct {
	Result         int    `json:"result"`
	Error          string `json:"error,omitempty"`
	ID             string `json:"id,omitempty"`
	DeletedFiles   int    `json:"deletedfiles,omitempty"`
	DeletedFolders int    `json:"deletedfolders,omitempty"`
}

type GetFileLinkResponse struct {
	Result  int           `json:"result"`
	Error   string        `json:"error,omitempty"`
	Path    string        `json:"path"`
	Hosts   []string      `json:"hosts"`
	Key     string        `json:"key,omitempty"`     // Encrypted file key (CEK) when getkey=1
	Expires string        `json:"expires,omitempty"` // Link expiration time
	Hash    NumericString `json:"hash,omitempty"`
	Size    int64         `json:"size,omitempty"`
	DwlTag  string        `json:"dwltag,omitempty"`
}

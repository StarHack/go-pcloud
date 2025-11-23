# go-pcloud

Provides a pure Go client compatible with the pCloud API. This supports both, plain file transfers and also pCloud's Crypto dirs. The crypto part was completely reverse engineered and described in detail in `CRYPTO.MD`.

## Features

- Login
- ListFolder
- DownloadFile(Stream)
  - plain
  - encrypted
- UploadFile(Stream)
  - plain
  - encrypted
- Delete
- Move
- Rename

## Installation

```bash
go get github.com/StarHack/go-pcloud
```

## Usage

Depending on your account's region it's important to choose the right endpoint:

- **USA:** `pcloud.EndpointAPI`
- **Europe:** `pcloud.EndpointEAPI`

### Basic Usage

```go
package main

import (
    "fmt"
    "os"
    "github.com/StarHack/go-pcloud/pcloud"
)

func main() {
    // Login
    client, err := pcloud.NewClient("your-email@example.com", "your-password", "", pcloud.EndpointAPI)
    if err != nil {
        fmt.Printf("Failed to login: %v\n", err)
        os.Exit(1)
    }

    // Upload a file to the root folder
    metadata, err := client.UploadFile(0, "file.txt")
    if err != nil {
        fmt.Printf("Failed to upload file: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("Uploaded file with ID: %d\n", metadata.FileID)

    // Download the file
    err = client.DownloadFile(int64(metadata.FileID), "/path/to/downloaded/file.txt")
    if err != nil {
        fmt.Printf("Failed to download file: %v\n", err)
        os.Exit(1)
    }
    fmt.Println("File downloaded successfully")

    // List contents of root folder
    entries, err := client.ListFolder(0)
    if err != nil {
        fmt.Printf("Failed to list folder: %v\n", err)
        os.Exit(1)
    }
    for _, entry := range entries {
        fmt.Printf("- %s (%s)\n", entry.Name, entry.Type())
    }
}
```

### Encrypted Operations

For encrypted folders, provide your crypto password when creating the client. The methods to use are the same but the implementation will automatically encrypt/decrypt under the hood.

```go
package main

import (
    "fmt"
    "os"
    "github.com/StarHack/go-pcloud/pcloud"
)

func main() {
    // Create a client with crypto password for encrypted operations
    client, err := pcloud.NewClient("your-email@example.com", "your-password", "your-crypto-password", pcloud.EndpointAPI)
    if err != nil {
        fmt.Printf("Failed to login: %v\n", err)
        os.Exit(1)
    }

    // Upload to an encrypted folder (replace 12345 with actual encrypted folder ID)
    encryptedFolderID := int64(12345)
    metadata, err := client.UploadFile(encryptedFolderID, "file.txt")
    if err != nil {
        fmt.Printf("Failed to upload encrypted file: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("Uploaded encrypted file with ID: %d\n", metadata.FileID)

    // Download encrypted file (automatically decrypted)
    err = client.DownloadFile(int64(metadata.FileID), "/path/to/decrypted/file.txt")
    if err != nil {
        fmt.Printf("Failed to download encrypted file: %v\n", err)
        os.Exit(1)
    }
    fmt.Println("Encrypted file downloaded and decrypted successfully")
}
```

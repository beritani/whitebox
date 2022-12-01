package core

import (
	"encoding/json"
	"fmt"

	"github.com/decred/dcrd/hdkeychain/v3"
)

// File ...
type File struct {
	Key        *hdkeychain.ExtendedKey
	KeyFile    KeyFile
	MetaBlocks []EncryptedBlock
	FileBlocks []EncryptedBlock
}

// Meta ...
type Meta struct {
	Name string   `json:"Name"`
	Type string   `json:"Type"`
	Tags []string `json:"Tags"`
}

// CreateFile returns a file object
func CreateFile(parent *hdkeychain.ExtendedKey, index uint32, meta Meta, data []byte, size int, version uint32) (File, error) {
	if index < 1 {
		return File{}, fmt.Errorf("Index must be greater than 0")
	}

	fileKey, err := parent.Child(index)
	if err != nil {
		return File{}, err
	}

	// Create Key File
	keyFile, err := CreateKeyFile(fileKey, version)
	if err != nil {
		return File{}, err
	}

	publicKey, err := keyFile.PublicKey()
	if err != nil {
		return File{}, nil
	}

	// Create Meta Blocks
	metaID := FileID(publicKey, keyFile.MetaSalt)

	var metaData []byte
	if meta.Type == "" {
		metaData = []byte{}
	} else {
		metaData, err = json.Marshal(meta)
		if err != nil {
			return File{}, err
		}
	}

	encryptedMetaBlocks, err := CreateEncryptedBlocks(metaID, keyFile.Key(), metaData, size)
	if err != nil {
		return File{}, err
	}

	// Create File Blocks
	fileID := FileID(publicKey, keyFile.FileSalt)
	encryptedFileBlocks, err := CreateEncryptedBlocks(fileID, keyFile.Key(), data, size)
	if err != nil {
		return File{}, err
	}

	return File{
		Key:        keyFile.file,
		KeyFile:    keyFile,
		MetaBlocks: encryptedMetaBlocks,
		FileBlocks: encryptedFileBlocks,
	}, nil
}

// CreateFolder ...
func CreateFolder(parent *hdkeychain.ExtendedKey, index uint32, meta Meta, size int) (File, error) {
	return CreateFile(parent, index, meta, []byte{}, size, 0)
}

// RecreateFile ...
func RecreateFile(blocks []Block) []byte {
	totalSize := 0
	for i := range blocks {
		totalSize += len(blocks[i].Data)
	}

	data := make([]byte, totalSize)
	var i int
	for _, block := range blocks {
		i += copy(data[i:], block.Data)
	}

	return data
}

// ParseMeta ...
func ParseMeta(data []byte) (Meta, error) {
	var meta Meta
	err := json.Unmarshal(data, &meta)
	if err != nil {
		return Meta{}, err
	}
	return meta, nil
}

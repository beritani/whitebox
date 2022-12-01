package client

import (
	"sync"

	"github.com/beritani/whitebox/core"
	"github.com/decred/dcrd/hdkeychain/v3"
)

// NewClient returns a new client form mnemonic and password
func NewClient(mnemonic string, password string, size int, handlers Handlers) (*Client, error) {
	var err error
	var masterKey *hdkeychain.ExtendedKey

	if mnemonic == "" {
		mnemonic, masterKey, err = core.NewRootFolder(password)
	} else {
		mnemonic, masterKey, err = core.GetRootFolder(mnemonic, password)
	}

	if err != nil {
		return nil, err
	}

	root := Folder{
		File: File{
			Index: 0,
			Path:  "/",
			Meta: &core.Meta{
				Name: "root",
				Type: "folder",
			},
		},
		Key:      masterKey,
		Children: map[uint32]Folder{},
	}

	root.Parent = &root

	return &Client{
		Mnemonic:  mnemonic,
		masterKey: masterKey,
		handlers:  handlers,
		pwd:       &root,
		root:      &root,
		Size:      size,
		mutex:     &sync.Mutex{},
	}, nil
}

// NewClientFromKey returns a new client from an extended key string
func NewClientFromKey(key string, size int, handlers Handlers) (*Client, error) {
	masterKey, err := core.GetRootFolderFromKey(key)
	if err != nil {
		return nil, err
	}

	root := Folder{
		File: File{
			Index: 0,
			Path:  "/",
			Meta: &core.Meta{
				Name: "root",
				Type: "folder",
			},
		},
		Key:      masterKey,
		Children: map[uint32]Folder{},
	}

	root.Parent = &root

	return &Client{
		masterKey: masterKey,
		handlers:  handlers,
		root:      &root,
		pwd:       &root,
		Size:      size,
		mutex:     &sync.Mutex{},
	}, nil
}

package client

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/beritani/whitebox/core"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
)

// Handlers Abstract Interface
type Handlers interface {
	Upload(id string, data []byte) error
	Download(id string) ([]byte, error)
	Delete(id string) error
	Exists(id string) bool
}

// File Object
type File struct {
	Index     uint32
	KeyFile   *core.KeyFile
	Meta      *core.Meta
	PublicKey *secp256k1.PublicKey
	Parent    *Folder
	Path      string
}

// Folder Object
type Folder struct {
	File
	Key      *hdkeychain.ExtendedKey
	Children map[uint32]Folder
}

// Client Object
type Client struct {
	Mnemonic  string
	Size      int
	mutex     *sync.Mutex
	masterKey *hdkeychain.ExtendedKey
	pwd       *Folder
	root      *Folder
	handlers  Handlers
}

// ID returns a hash of the public key
func (c *Client) ID() string {
	publicKey, _ := core.GetPublicKeyFromHDKey(c.masterKey)
	return core.KeyID(publicKey)
}

func (c *Client) getBlock(key []byte, fileID string, index int) (core.Block, error) {
	blockID := core.BlockID(fileID, index)
	blockData, err := c.handlers.Download(blockID)
	if err != nil {
		return core.Block{}, err
	}

	encryptedBlock := core.EncryptedBlock{
		ID:   blockID,
		Data: blockData,
	}

	block, err := encryptedBlock.Decrypt(key)
	if err != nil {
		return core.Block{}, err
	}

	return block, nil
}

func (c *Client) getBlocks(key []byte, fileID string) ([]core.Block, error) {
	block0, err := c.getBlock(key, fileID, 0)
	if err != nil {
		return nil, err
	}

	blocks := make([]core.Block, block0.Count)
	blocks[0] = block0

	for i := 1; i < block0.Count; i++ {
		block, err := c.getBlock(key, fileID, i)
		if err != nil {
			return nil, err
		}
		blocks[i] = block
	}

	return blocks, nil
}

func (c *Client) getBlockIds(key []byte, fileID string) ([]string, error) {
	block0, err := c.getBlock(key, fileID, 0)
	if err != nil {
		return nil, err
	}

	blockIDs := make([]string, block0.Count)
	for i := 0; i < block0.Count; i++ {
		blockIDs[i] = core.BlockID(fileID, i)
	}

	return blockIDs, nil
}

func (c *Client) getKeyFile(parent *Folder, index uint32) (*core.KeyFile, error) {
	// Check Key File Exists
	file := parent.Children[index]
	if !file.KeyFile.MissingData() {
		return file.KeyFile, nil
	}

	// Check Key Exists
	if file.Key == nil {
		fileKey, err := parent.Key.Child(index)
		if err != nil {
			return nil, err
		}
		file.Key = fileKey
		parent.Children[index] = file
	}

	// Check Public Key Exists
	if file.PublicKey == nil {
		publicKey, err := core.GetPublicKeyFromHDKey(file.Key)
		if err != nil {
			return nil, err
		}
		file.PublicKey = publicKey
		parent.Children[index] = file
	}

	// Get Key File
	keyID := core.KeyID(file.PublicKey)
	if !c.handlers.Exists(keyID) {
		return nil, nil
	}

	keyData, err := c.handlers.Download(keyID)
	if err != nil {
		return nil, err
	}

	keyFile, err := core.ParseKeyFile(file.Key, keyData)
	if err != nil {
		return nil, err
	}

	// Save Key File
	file.KeyFile = &keyFile
	parent.Children[index] = file

	return file.KeyFile, nil
}

func (c *Client) getMeta(parent *Folder, index uint32) (*core.Meta, error) {
	// Check Already Exists
	file := parent.Children[index]
	if file.Meta != nil {
		return file.Meta, nil
	}

	// Get Key File
	keyFile, err := c.getKeyFile(parent, index)
	if err != nil {
		return nil, err
	}

	// Recreate Meta
	metaID := core.FileID(file.PublicKey, keyFile.MetaSalt)
	metaBlocks, err := c.getBlocks(keyFile.Key(), metaID)
	if err != nil {
		return nil, err
	}

	metaData := core.RecreateFile(metaBlocks)
	metaFile, err := core.ParseMeta(metaData)
	if err != nil {
		return nil, err
	}

	// Save Meta Data
	file.Meta = &metaFile
	parent.Children[index] = file

	return file.Meta, nil
}

func (c *Client) getPath(parent *Folder, index uint32) string {
	file := parent.Children[index]
	if file.Path == "" {
		file.Path = filepath.Clean(fmt.Sprintf("%s/%v", parent.Path, index))
		parent.Children[index] = file
	}
	return file.Path
}

func (c *Client) getFileDetails(parent *Folder, index uint32) (*Folder, error) {
	// Check Already
	if _, ok := parent.Children[index]; !ok {
		parent.Children[index] = Folder{
			File: File{
				Index:  index,
				Parent: parent,
			},
			Children: map[uint32]Folder{},
		}
	}

	keyFile, err := c.getKeyFile(parent, index)
	if err != nil {
		delete(parent.Children, index)
		return nil, err
	}

	if keyFile == nil {
		delete(parent.Children, index)
		return nil, nil
	}

	meta, err := c.getMeta(parent, index)
	if err != nil {
		delete(parent.Children, index)
		return nil, err
	}

	if meta == nil {
		delete(parent.Children, index)
		return nil, nil
	}

	c.getPath(parent, index)

	file := parent.Children[index]

	return &file, nil
}

func (c *Client) getChildCount(parent *Folder) (uint32, error) {
	var i uint32 = 1
	for true {
		child, err := parent.Key.Child(i)
		if err != nil {
			return 0, err
		}

		publicKey, err := core.GetPublicKeyFromHDKey(child)
		if err != nil {
			return 0, err
		}

		id := core.KeyID(publicKey)
		if !c.handlers.Exists(id) {
			break
		}

		i++
	}

	return i - 1, nil
}

func (c *Client) uploadFile(file core.File) error {
	// Encrypt and Upload Key File
	encryptedKeyFile := file.KeyFile.Encrypt()
	keyID, err := encryptedKeyFile.ID()
	if err != nil {
		return err
	}

	encryptedKeyFileData, err := encryptedKeyFile.Serialise()
	if err != nil {
		return err
	}

	err = c.handlers.Upload(keyID, encryptedKeyFileData)
	if err != nil {
		return err
	}

	// Upload Meta Blocks
	for _, block := range file.MetaBlocks {
		err := c.handlers.Upload(block.ID, block.Data)
		if err != nil {
			return err
		}
	}

	// Upload File Blocks
	for _, block := range file.FileBlocks {
		err := c.handlers.Upload(block.ID, block.Data)
		if err != nil {
			return err
		}
	}

	return nil
}

// Pwd ...
func (c *Client) Pwd() *Folder {
	return c.pwd
}

// PwdString ...
func (c *Client) PwdString() string {
	path := ""
	folder := c.pwd
	for true {
		if folder.Parent == folder {
			path = "/" + path
			break
		}
		path = strconv.FormatUint(uint64(folder.Index), 10) + "/" + path
		folder = folder.Parent
	}
	return filepath.Clean(path)
}

// Root ...
func (c *Client) Root() *Folder {
	return c.root
}

// GetExtendedPublicKey ...
func (c *Client) GetExtendedPublicKey(file *Folder) string {
	return file.Key.Neuter().String()
}

// GetFolderFromPath ...
func (c *Client) GetFolderFromPath(folder *Folder, path string) (*Folder, error) {
	path = filepath.Clean(path)
	if path[0] == '/' {
		folder = c.Root()
	}

	for _, i := range strings.Split(path, "/") {
		switch i {
		case "":
			continue
		case ".":
			continue
		case "..":
			folder = c.pwd.Parent
		default:
			index, err := strconv.ParseInt(i, 10, 0)
			if err != nil {
				return nil, err
			}
			folder, err = c.getFileDetails(folder, uint32(index))
			if err != nil {
				return nil, err
			}
		}
	}

	return folder, nil
}

// Cd ...
func (c *Client) Cd(path string) (*Folder, error) {
	path = filepath.Clean(path)

	if path[0] == '/' {
		c.pwd = c.root
	}

	folder, err := c.GetFolderFromPath(c.pwd, path)
	if err != nil {
		return nil, err
	}
	c.pwd = folder

	return c.pwd, nil
}

// Ls ...
func (c *Client) Ls(folder *Folder) map[uint32]Folder {
	var i uint32 = 1
	for true {
		file, err := c.getFileDetails(folder, i)
		if err != nil {
			delete(folder.Children, i)
			break
		}
		if file == nil {
			delete(folder.Children, i)
			break
		}
		i++
	}
	return folder.Children
}

// Refresh ...
func (c *Client) Refresh(parent *Folder) {
	parent.Children = map[uint32]Folder{}
	c.Ls(parent)
}

// Mkdir ...
func (c *Client) Mkdir(parent *Folder, meta core.Meta) (*Folder, error) {
	meta.Type = "folder"
	count, err := c.getChildCount(parent)
	if err != nil {
		return nil, err
	}
	index := count + 1

	file, err := core.CreateFolder(parent.Key, index, meta, c.Size)
	if err != nil {
		return nil, err
	}

	err = c.uploadFile(file)
	if err != nil {
		return nil, err
	}

	folder := Folder{
		File: File{
			Index:   index,
			KeyFile: &file.KeyFile,
			Meta:    &meta,
			Parent:  parent,
		},
		Children: map[uint32]Folder{},
		Key:      file.Key,
	}

	parent.Children[index] = folder

	return &folder, nil
}

// Rm ...
func (c *Client) Rm(folder *Folder) error {
	c.Refresh(folder.Parent)

	// Get IDs
	keyID, err := folder.KeyFile.ID()
	if err != nil {
		return err
	}

	var metaBlockIds []string
	var fileBlockIds []string

	file, err := c.getFileDetails(folder.Parent, folder.Index)
	if err != nil {
		return err
	}

	metaID := core.FileID(file.PublicKey, file.KeyFile.MetaSalt)
	metaBlockIds, err = c.getBlockIds(file.KeyFile.Key(), metaID)
	if err != nil {
		return err
	}

	if file.Meta.Type == "file" {
		fileID := core.FileID(file.PublicKey, file.KeyFile.FileSalt)
		fileBlockIds, err = c.getBlockIds(file.KeyFile.Key(), fileID)
		if err != nil {
			return err
		}
	}

	// Delete Files
	err = c.handlers.Delete(keyID)
	if err != nil {
		return err
	}

	for _, id := range metaBlockIds {
		err := c.handlers.Delete(id)
		if err != nil {
			return err
		}
	}

	for _, id := range fileBlockIds {
		err := c.handlers.Delete(id)
		if err != nil {
			return err
		}
	}

	// Create New Files
	version, err := file.KeyFile.GetVersion()
	if err != nil {
		return err
	}

	newFile, err := core.CreateFile(file.Parent.Key, folder.Index, core.Meta{}, []byte{}, c.Size, version+1)
	if err != nil {
		return err
	}

	err = c.uploadFile(newFile)
	if err != nil {
		return err
	}

	c.Refresh(folder.Parent)

	return nil
}

// Upload ...
func (c *Client) Upload(parent *Folder, meta core.Meta, data []byte) error {
	meta.Type = "file"
	count, err := c.getChildCount(parent)
	if err != nil {
		return err
	}
	index := count + 1

	file, err := core.CreateFile(parent.Key, index, meta, data, c.Size, 0)
	if err != nil {
		return err
	}

	err = c.uploadFile(file)
	if err != nil {
		return err
	}
	return nil
}

// Download ...
func (c *Client) Download(folder *Folder, index uint32) ([]byte, error) {
	keyFile, err := c.getKeyFile(folder, index)

	publicKey, err := keyFile.PublicKey()
	if err != nil {
		return nil, err
	}

	// Recreate File
	fileID := core.FileID(publicKey, keyFile.FileSalt)
	fileBlocks, err := c.getBlocks(keyFile.Key(), fileID)
	if err != nil {
		return nil, err
	}
	fileData := core.RecreateFile(fileBlocks)

	return fileData, nil
}

// Find ...
func (c *Client) Find(folder *Folder, query string, ret []Folder) ([]Folder, error) {
	if ret == nil {
		ret = make([]Folder, 0, 0)
	}

	count, err := c.getChildCount(folder)
	if err != nil {
		return ret, err
	}

	if count == 0 {
		for _, tag := range folder.Meta.Tags {
			if tag == query {
				ret = append(ret, *folder)
			}
		}
		return ret, nil
	}

	children := c.Ls(folder)
	for _, child := range children {
		results, err := c.Find(&child, query, nil)
		if err != nil {
			return ret, err
		}

		ret = append(ret, results...)
	}

	return ret, nil
}

package core

import (
	"encoding/json"
	"math"
)

// Block Object
type Block struct {
	id      string
	Data    []byte
	Padding int
	Count   int
}

// EncryptedBlock Object
type EncryptedBlock struct {
	ID   string
	Data []byte
}

// Encrypt ...
func (b Block) Encrypt(key []byte) (EncryptedBlock, error) {
	// Marshal Block
	blockData, err := json.Marshal(b)
	if err != nil {
		return EncryptedBlock{}, err
	}

	// Encrypt Block Data
	encryptedBlockData, err := Encrypt(key, blockData)
	if err != nil {
		return EncryptedBlock{}, err
	}

	return EncryptedBlock{
		ID:   b.id,
		Data: encryptedBlockData,
	}, nil
}

// Decrypt ...
func (b EncryptedBlock) Decrypt(key []byte) (Block, error) {
	// Decrypt Data
	blockData, err := Decrypt(key, b.Data)
	if err != nil {
		return Block{}, err
	}

	// Unmarshal
	var block Block
	err = json.Unmarshal(blockData, &block)
	if err != nil {
		return Block{}, err
	}

	block.Data = block.Data[:len(block.Data)-block.Padding]

	return block, nil
}

// CreateBlocks ...
func CreateBlocks(fileID string, data []byte, size int) []Block {
	count := int(math.Ceil(float64(len(data)) / float64(size)))
	blocks := make([]Block, count)

	for i := range blocks {
		slice := make([]byte, size)
		padding := copy(slice, data[i*size:])
		blocks[i] = Block{
			id:      BlockID(fileID, i),
			Count:   count,
			Data:    slice,
			Padding: size - padding,
		}
	}
	return blocks
}

// CreateEncryptedBlocks ...
func CreateEncryptedBlocks(fileID string, key []byte, data []byte, size int) (encryptedBlocks []EncryptedBlock, err error) {
	blocks := CreateBlocks(fileID, data, size)
	encryptedBlocks = make([]EncryptedBlock, len(blocks))
	for i, block := range blocks {
		encryptedBlocks[i], err = block.Encrypt(key)
		if err != nil {
			return nil, err
		}
	}
	return encryptedBlocks, nil
}

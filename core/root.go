package core

import (
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/tyler-smith/go-bip39"
)

// GetRootFolder returns a root extended key from mnemonic and password
func GetRootFolder(mnemonic string, password string) (string, *hdkeychain.ExtendedKey, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, password)
	if err != nil {
		return "", nil, err
	}

	masterKey, err := hdkeychain.NewMaster(seed, chaincfg.MainNetParams())
	if err != nil {
		return "", nil, err
	}

	key, _ := masterKey.Child(hdkeychain.HardenedKeyStart + 44)
	key, _ = key.Child(hdkeychain.HardenedKeyStart)
	key, _ = key.Child(hdkeychain.HardenedKeyStart)
	key, _ = key.Child(0)

	return mnemonic, key, nil
}

// GetRootFolderFromKey retuns the root extended key
func GetRootFolderFromKey(key string) (*hdkeychain.ExtendedKey, error) {
	masterKey, err := hdkeychain.NewKeyFromString(key, chaincfg.MainNetParams())
	if err != nil {
		return nil, err
	}
	return masterKey, nil
}

// GetMnemonic returns a randomly generated mnemonic seed
func GetMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

// NewRootFolder returns a new random root extended key and mnemonic
func NewRootFolder(password string) (string, *hdkeychain.ExtendedKey, error) {
	mnemonic, err := GetMnemonic()
	if err != nil {
		return "", nil, err
	}

	return GetRootFolder(mnemonic, password)
}

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
)

// RandomBytes returns an array of random bytes for a given length
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GetPublicKeyFromHDKey returns the public key for an extended key
func GetPublicKeyFromHDKey(key *hdkeychain.ExtendedKey) (*secp256k1.PublicKey, error) {
	pubBytes := key.SerializedPubKey()
	publicKey, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

// GetPrivateKeyFromHDKey returns the private key for an extended key
func GetPrivateKeyFromHDKey(key *hdkeychain.ExtendedKey) (*secp256k1.PrivateKey, error) {
	privBytes, err := key.SerializedPrivKey()
	if err != nil {
		return nil, err
	}
	privateKey := secp256k1.PrivKeyFromBytes(privBytes)
	return privateKey, nil
}

// Encrypt returns encrypted cipher text
func Encrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce, err := RandomBytes(12)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encrypted := aesgcm.Seal(nil, nonce, data, nil)

	return append(nonce, encrypted...), nil
}

// Decrypt retuns decrypted plain text
func Decrypt(key []byte, data []byte) ([]byte, error) {
	nonce := data[:12]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	decrypted, err := aesgcm.Open(nil, nonce, data[12:], nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

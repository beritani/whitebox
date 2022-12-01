package core

import (
	"encoding/hex"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// KeyID returns the key id for a public key
func KeyID(publicKey *secp256k1.PublicKey) string {
	hash := sha3.New256()
	hash.Write(publicKey.SerializeCompressed())
	hash.Write([]byte("key"))
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum)
}

// FileID returns the file id for a public key
func FileID(publicKey *secp256k1.PublicKey, salt []byte) string {
	hash := sha3.New256()
	hash.Write(publicKey.SerializeCompressed())
	hash.Write([]byte("file"))
	hash.Write(salt)
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum)
}

// BlockID returns the block id for a public key
func BlockID(fileID string, index int) string {
	hash := sha3.New256()
	hash.Write([]byte(fileID))
	hash.Write([]byte("block"))
	hash.Write([]byte(strconv.Itoa(index)))
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum)
}

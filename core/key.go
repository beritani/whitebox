package core

import (
	"encoding/json"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/decred/dcrd/hdkeychain/v3"
	"golang.org/x/crypto/sha3"
)

// KeyFile ...
type KeyFile struct {
	id        string
	file      *hdkeychain.ExtendedKey
	key       []byte
	Version   []byte
	MetaSalt  []byte
	FileSalt  []byte
	EphemKey  []byte
	Signature []byte
}

// MissingData returns true if fields are missing from key file
func (f *KeyFile) MissingData() bool {
	if f == nil {
		return true
	}
	return (f.file == nil) || (len(f.key) == 0) || ((len(f.Version) == 0) || (len(f.MetaSalt) == 0) || (len(f.FileSalt) == 0) || (len(f.EphemKey) == 0) || (len(f.Signature) == 0))
}

// Encrypt returns the encrypted key file
func (f *KeyFile) Encrypt() KeyFile {
	encryptedKeyFile := KeyFile{
		key:       f.key,
		file:      f.file,
		EphemKey:  f.EphemKey,
		Signature: f.Signature,
	}

	// Encrypt Salts
	encryptedKeyFile.MetaSalt, _ = Encrypt(f.key, f.MetaSalt)
	encryptedKeyFile.FileSalt, _ = Encrypt(f.key, f.FileSalt)
	encryptedKeyFile.Version, _ = Encrypt(f.key, f.Version)

	return encryptedKeyFile
}

// Decrypt returns the decrypted key file
func (f *KeyFile) Decrypt() KeyFile {
	decryptedKeyFile := KeyFile{
		key:       f.key,
		file:      f.file,
		EphemKey:  f.EphemKey,
		Signature: f.Signature,
	}

	// Decrypt
	decryptedKeyFile.MetaSalt, _ = Decrypt(f.key, f.MetaSalt)
	decryptedKeyFile.FileSalt, _ = Decrypt(f.key, f.FileSalt)
	decryptedKeyFile.Version, _ = Decrypt(f.key, f.Version)

	return decryptedKeyFile
}

// GetVersion returns the version of the key file
func (f *KeyFile) GetVersion() (uint32, error) {
	version, err := strconv.ParseInt(string(f.Version), 10, 0)
	return uint32(version), err
}

// Verify returns true if the signature is valid
func (f *KeyFile) Verify() (bool, error) {
	// Generate Signature
	hash := sha3.New256()
	hash.Write(f.MetaSalt)
	hash.Write(f.FileSalt)
	hash.Write(f.Version)
	hash.Write(f.EphemKey)

	sig, err := ecdsa.ParseDERSignature(f.Signature)
	if err != nil {
		return false, err
	}

	version, err := f.GetVersion()
	if err != nil {
		return false, err
	}

	ownerKey, err := OwnershipPublicKey(f.file, version)
	if err != nil {
		return false, err
	}

	return sig.Verify(hash.Sum(nil), ownerKey), nil
}

// Key returns the key file encryption key
func (f *KeyFile) Key() []byte {
	return f.key
}

// ID returns the key id
func (f *KeyFile) ID() (string, error) {
	publicKey, err := f.PublicKey()
	if err != nil {
		return "", err
	}
	return KeyID(publicKey), nil
}

// File returns the file struct
func (f *KeyFile) File() *hdkeychain.ExtendedKey {
	return f.file
}

// PublicKey returns the public key for the key file
func (f *KeyFile) PublicKey() (*secp256k1.PublicKey, error) {
	return GetPublicKeyFromHDKey(f.file)
}

// Serialise returns the marshalled key file
func (f *KeyFile) Serialise() ([]byte, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return data, err
}

// OwnershipPrivateKey returns the private key for a given version
func OwnershipPrivateKey(hdkey *hdkeychain.ExtendedKey, version uint32) (*secp256k1.PrivateKey, error) {
	child, err := hdkey.Child(0)
	if err != nil {
		return nil, err
	}

	priv, err := child.Child(version)
	if err != nil {
		return nil, err
	}

	privBytes, err := priv.SerializedPrivKey()
	if err != nil {
		return nil, err
	}

	return secp256k1.PrivKeyFromBytes(privBytes), nil
}

// OwnershipPublicKey returns the public key for a given version
func OwnershipPublicKey(hdkey *hdkeychain.ExtendedKey, version uint32) (*secp256k1.PublicKey, error) {
	child, err := hdkey.Child(0)
	if err != nil {
		return nil, err
	}

	pub, err := child.Child(version)
	if err != nil {
		return nil, err
	}

	pubBytes := pub.SerializedPubKey()
	publicKey, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

// CreateKeyFile returns a new key file for an extended key
func CreateKeyFile(hdkey *hdkeychain.ExtendedKey, version uint32) (KeyFile, error) {
	// Get Public Key
	publicKey, err := GetPublicKeyFromHDKey(hdkey)
	if err != nil {
		return KeyFile{}, err
	}

	// Generate Salts
	metaSalt, _ := RandomBytes(16)
	fileSalt, _ := RandomBytes(16)

	// Generate Encryption Key
	ephemKey, _ := secp256k1.GeneratePrivateKey()
	key := secp256k1.GenerateSharedSecret(ephemKey, publicKey)

	// Create Key File
	keyFile := KeyFile{
		key:      key,
		file:     hdkey,
		MetaSalt: metaSalt,
		FileSalt: fileSalt,
		Version:  []byte(strconv.Itoa(int(version))),
		EphemKey: ephemKey.PubKey().SerializeUncompressed(),
	}

	// Generate Signature
	hash := sha3.New256()
	hash.Write(keyFile.MetaSalt)
	hash.Write(keyFile.FileSalt)
	hash.Write(keyFile.Version)
	hash.Write(keyFile.EphemKey)

	// Verify Owner
	ownerKey, err := OwnershipPrivateKey(hdkey, uint32(version))
	if err != nil {
		return keyFile, nil
	}

	sig := ecdsa.Sign(ownerKey, hash.Sum(nil))
	keyFile.Signature = sig.Serialize()

	return keyFile, nil
}

// ParseKeyFile returns a parsed key file
func ParseKeyFile(hdkey *hdkeychain.ExtendedKey, data []byte) (KeyFile, error) {
	// Get Private Key
	privBytes, err := hdkey.SerializedPrivKey()
	privateKey := secp256k1.PrivKeyFromBytes(privBytes)
	if err != nil {
		return KeyFile{}, err
	}

	// Unmarshal Data
	var encryptedKeyFile KeyFile
	err = json.Unmarshal(data, &encryptedKeyFile)
	if err != nil {
		return KeyFile{}, err
	}

	// Get Encryption Key
	ephemKey, err := secp256k1.ParsePubKey(encryptedKeyFile.EphemKey)
	if err != nil {
		return KeyFile{}, err
	}

	encryptedKeyFile.key = secp256k1.GenerateSharedSecret(privateKey, ephemKey)
	encryptedKeyFile.file = hdkey

	// Decrypt
	keyFile := encryptedKeyFile.Decrypt()

	return keyFile, nil
}

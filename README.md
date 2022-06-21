# Whitebox

Whitebox is an encrypted file store library for backing up files in a fully encrypted and anonymous manner. It uses technologies and methods used in crypto-currencies to deterministically generate encryption keys.

This library contains the core functionality for creating, downloading and verifying files.

---

## Functionality

### Key Deriviation

Whitebox uses [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) to generate public and private keys using a 12-word mnemonic. This mnemonic can be used along with a password to deterministically generate keys.

Each file has its own key pair dervived using the parent folder private/public key, chaincode and index.

---

## Components

### IDs

- Key ID: hash(publicKey)
- Meta ID: hash(publicKey, metaSalt)
- File ID: hash(publicKey, fileSalt)
- Block ID: hash(fileId, index)

### Meta File

The meta file is a json object that stores information about the file

| Key      | Description                            |
| -------- | -------------------------------------- |
| filename | File name for file/folder              |
| type     | Specifies file type "file" or "folder" |

### Key File

The key file is used to store cryptographic material such as the public key and encrypted salts

| Index | Length | Name                   | Description                                                  |
| ----- | ------ | ---------------------- | ------------------------------------------------------------ |
| 0     | 33     | Public Key             | Used to generate AES key for encryption                      |
| 33    | 16     | Meta ID Salt IV        | Used to encrypt meta file ID salt                            |
| 49    | 16     | Encrypted Meta ID Salt | Used to generate meta file ID                                |
| 65    | 16     | File ID Salt IV        | Used to encrypt file ID salt                                 |
| 81    | 16     | Encrypted File ID Salt | Used to generate file ID                                     |
| 97    | 16     | Signature              | Used to verify ownership of file and allow updating/deletion |

### Block File

Each block file stored is the same size and

| Index | Length | Name           | Description                                     |
| ----- | ------ | -------------- | ----------------------------------------------- |
| 0     | 3      | Block Count    | Number of blocks in file                        |
| 3     | 3      | Padding Count  | Amount of padding in block                      |
| 6     | 16     | IV             | IV used to encrypted block data                 |
| 22    | 1 =<   | Encrypted Data | Concated data and padding after being encrypted |

## License

Please see [LICENSE](./LICENSE)

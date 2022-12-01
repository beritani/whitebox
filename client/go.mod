module github.com/beritani/whitebox/client

go 1.17

replace github.com/beritani/whitebox/core => ../core

require (
	github.com/beritani/whitebox/core v0.0.0-00010101000000-000000000000
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.1.0
	github.com/decred/dcrd/hdkeychain/v3 v3.1.0
)

require (
	github.com/decred/base58 v1.0.3 // indirect
	github.com/decred/dcrd/chaincfg/chainhash v1.0.3 // indirect
	github.com/decred/dcrd/chaincfg/v3 v3.1.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.1 // indirect
	github.com/decred/dcrd/wire v1.5.0 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	golang.org/x/crypto v0.3.0 // indirect
	golang.org/x/sys v0.2.0 // indirect
)

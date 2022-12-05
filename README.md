# whitebox

Whitebox is an encrypted file store library for backing up files in a fully encrypted and anonymous manner. It uses technologies and methods used in crypto-currencies to deterministically generate encryption keys.

This library contains the core functionality for creating, downloading and verifying files.

## What is whitebox?

The two components are;

- whitebox core (this)
- whitebox react ui

The whitebox core repo (this) is a golang library that contains the code necessary to encrypt and decrypt files through the client module or using the api.

## Getting Started

### Docker

```bash
# Docker build command
docker build . --tag whitebox-api
```

```yaml
# docker-compose.yaml

version: "3"
services:
  whitebox-api:
    image: whitebox-api
    container_name: whitebox-api
    volumes:
      - ./data:/data
    environment:
      - API_HOST=0.0.0.0
      - API_PORT=8080
    ports:
      - 8080:8080
```

### Build from Source

```bash
# Build and run api
go build -o app .
mkdir data
DATA_PATH=./data ./app
```

## Disclaimer

I am a programmer not a cryptographer. Trust this code at your own risk.

## License

whitebox is licensed under the [copyfree](http://copyfree.org) ISC License.

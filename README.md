# prysmsh/pkg

Shared Go library for the Prysm ecosystem: internal utilities and **post-quantum cryptography (PQC) integration**.

## Overview

This package serves two purposes:

1. **Internal library** – Shared utilities and helpers used across Prysm services (backend, agent, CLI, etc.).
2. **PQC integration library** – Standalone post-quantum crypto primitives and TLS helpers for quantum-resistant deployments.

External projects can use the PQC packages directly for hybrid key exchange and TLS configuration.

## Packages

| Package | Description |
|---------|-------------|
| [`pqc`](./pqc) | Post-quantum hybrid KEM (X25519 + Kyber768) and AEAD encryption for DERP and mesh. |
| [`tlsutil`](./tlsutil) | TLS configuration helpers for PQC (e.g. `TLS_PQC_ENABLED` env toggle). |

## Installation

```bash
go get github.com/prysmsh/pkg
```

## Usage

### PQC – Hybrid key encapsulation

```go
import "github.com/prysmsh/pkg/pqc"

// Generate key pair
kp, err := pqc.GenerateKeyPair()
if err != nil {
    log.Fatal(err)
}

// Encapsulate (sender)
ciphertext, sharedSecret, err := pqc.Encapsulate(kp.PublicKey())

// Decapsulate (receiver)
sharedSecret, err := kp.Decapsulate(ciphertext)

// Encrypt/decrypt payload with shared secret
plaintext := []byte("hello")
ct, _ := pqc.EncryptPayload(sharedSecret, plaintext)
pt, _ := pqc.DecryptPayload(sharedSecret, ct)
```

### TLS – PQC configuration

```go
import (
    "crypto/tls"
    "github.com/prysmsh/pkg/tlsutil"
)

cfg := &tls.Config{MinVersion: tls.VersionTLS12}
tlsutil.ApplyPQCConfig(cfg)  // Uses TLS_PQC_ENABLED env (default: true)
```

## Requirements

- Go 1.21+
- For TLS PQC (X25519MLKEM768): Go 1.24+

## License

See the project root LICENSE file.

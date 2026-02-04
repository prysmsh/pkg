# prysmsh/pkg

[![Go Reference](https://pkg.go.dev/badge/github.com/prysmsh/pkg.svg)](https://pkg.go.dev/github.com/prysmsh/pkg)

Post-quantum cryptography and security utilities for Go. Hybrid KEM (X25519 + Kyber768), timing-safe comparison, secure random tokens, retry with backoff, and TLS PQC helpers.

**Maintained by [Prysm](https://prysm.sh).** Use in any Go project.

## Why prysmsh/pkg?

- **PQC-ready today** – Go 1.24+ uses X25519MLKEM768 by default; this library provides hybrid KEM and AEAD for application-layer encryption
- **Minimal dependencies** – cloudflare/circl, golang.org/x/crypto
- **Battle-tested** – Used in production across Prysm services (backend, agent, CLI, mesh)

## Packages

| Package | Description |
|---------|-------------|
| [`pqc`](./pqc) | Post-quantum hybrid KEM (X25519 + Kyber768) and AEAD encryption. |
| [`secure`](./secure) | Security primitives: constant-time comparison, secure random bytes, random hex tokens. |
| [`retry`](./retry) | Retry with exponential backoff (1s, 2s, 4s, ...). |
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

// Quick defaults (MinVersion TLS 1.2, PQC applied)
clientCfg := tlsutil.DefaultClientConfig()
serverCfg := tlsutil.DefaultServerConfig()

// Or apply to existing config
cfg := &tls.Config{MinVersion: tls.VersionTLS12}
tlsutil.ApplyPQCConfig(cfg)  // Uses TLS_PQC_ENABLED env (default: true)
```

### Secure – Timing-safe comparison and random tokens

```go
import "github.com/prysmsh/pkg/secure"

// Constant-time comparison (for tokens, CSRF, API keys)
if !secure.ConstantTimeEqual([]byte(got), []byte(want)) {
    return errors.New("invalid token")
}

// Secure random bytes and hex strings
id, _ := secure.RandomHex(32)  // 64-char hex string
bytes, _ := secure.RandomBytes(16)
```

### Retry – Exponential backoff

```go
import (
    "context"
    "github.com/prysmsh/pkg/retry"
)

err := retry.Do(ctx, 5, func() error {
    return doSomething()
})
// Stops on success, context cancel, or wrap errors with retry.ErrNonRetryable to skip retries
```

### Error handling

The `pqc` package exposes sentinel errors for programmatic handling:

```go
if errors.Is(err, pqc.ErrInvalidPublicKey) {
    // handle invalid public key
}
if errors.Is(err, pqc.ErrDecryptionFailed) {
    // handle tampered or corrupted ciphertext
}
```

## Examples

Runnable examples are in the [`examples/`](./examples) directory:

```bash
go run ./examples/pqc
go run ./examples/secure
go run ./examples/retry
```

## Requirements

- Go 1.21+
- For TLS PQC (X25519MLKEM768): Go 1.24+

## Versioning

This module follows [semantic versioning](https://semver.org/). The public API (packages `pqc`, `secure`, `retry`, and `tlsutil`) is stable. Breaking changes will result in a major version bump. The `internal/` package is not part of the public API.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

See the project root LICENSE file.

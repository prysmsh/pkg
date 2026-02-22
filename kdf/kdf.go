// Package kdf provides key derivation functions for secure key generation.
package kdf

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// HKDF derives a key of the given size from a secret using HKDF-SHA256.
// salt and info can be nil or empty; they are used for domain separation.
func HKDF(secret, salt, info []byte, size int) ([]byte, error) {
	if size <= 0 || size > 255*32 {
		return nil, errors.New("kdf: size must be 1-8160")
	}
	if len(secret) == 0 {
		return nil, errors.New("kdf: secret cannot be empty")
	}
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, size)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Argon2idParams holds recommended parameters for Argon2id.
type Argon2idParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

// DefaultArgon2idParams returns OWASP-recommended parameters.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Time:    3,
		Memory:  64 * 1024, // 64 MiB
		Threads: 4,
		KeyLen:  32,
	}
}

// Argon2id derives a key from a password using Argon2id.
// salt should be at least 16 bytes, cryptographically random.
// threads controls parallelism (number of lanes); use DefaultArgon2idParams() for recommended values.
func Argon2id(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("kdf: password cannot be empty")
	}
	if len(salt) < 8 {
		return nil, errors.New("kdf: salt must be at least 8 bytes")
	}
	if keyLen == 0 || keyLen > 64 {
		return nil, errors.New("kdf: keyLen must be 1-64")
	}
	if threads == 0 {
		threads = 1
	}
	return argon2.IDKey(password, salt, time, memory, threads, keyLen), nil
}

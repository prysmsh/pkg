// Package secure provides security primitives for timing-safe comparison and
// cryptographically secure random generation.
package secure

import (
	"crypto/rand"
	"encoding/hex"
	"io"

	"crypto/subtle"
)

// ConstantTimeEqual returns true iff a and b are equal.
// Uses constant-time comparison to prevent timing attacks on tokens, CSRF values, and API keys.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomHex returns a hex-encoded string of n random bytes (2*n hex characters).
// Useful for generating IDs, tokens, and nonces.
func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

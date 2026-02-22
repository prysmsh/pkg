package util

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

// SecureCompare performs constant-time byte comparison to prevent timing attacks.
// Use for comparing tokens, secrets, or authentication credentials.
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// SecureToken generates a cryptographically secure random token of the given byte length.
// The returned string is hex-encoded (2 chars per byte).
// Typical use: SecureToken(32) for 32-byte (256-bit) tokens.
func SecureToken(size int) (string, error) {
	if size <= 0 || size > 65536 {
		return "", errors.New("secure token size must be 1-65536 bytes")
	}
	b, err := SecureBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SecureBytes fills the given slice with cryptographically secure random bytes.
// Returns an error if size is invalid or rand.Read fails.
func SecureBytes(size int) ([]byte, error) {
	if size <= 0 || size > 65536 {
		return nil, errors.New("secure bytes size must be 1-65536")
	}
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

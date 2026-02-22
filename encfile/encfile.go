// Package encfile provides a versioned encrypted storage format for secrets at rest.
package encfile

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version    = 1
	NonceSize  = chacha20poly1305.NonceSizeX
	KeySize    = 32
	HeaderSize = 1 + NonceSize // version + nonce
)

// Encrypt encrypts plaintext with the given key.
// Output format: version(1) || nonce(12) || ciphertext (plaintext + 16-byte tag).
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("key must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, HeaderSize+len(ciphertext))
	out = append(out, byte(Version))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt decrypts ciphertext produced by Encrypt.
func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("key must be 32 bytes")
	}
	if len(ciphertext) < HeaderSize {
		return nil, errors.New("ciphertext too short")
	}
	if ciphertext[0] != Version {
		return nil, errors.New("unsupported ciphertext version")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[1 : 1+NonceSize]
	ct := ciphertext[HeaderSize:]
	return aead.Open(nil, nonce, ct, nil)
}

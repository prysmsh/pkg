package pqc

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = chacha20poly1305.NonceSizeX

// EncryptPayload encrypts plaintext with the shared secret from hybrid KEM.
// Format: nonce (12 bytes) || ciphertext (plaintext + 16-byte tag).
func EncryptPayload(sharedSecret [SharedSecretSize]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// DecryptPayload decrypts ciphertext produced by EncryptPayload.
func DecryptPayload(sharedSecret [SharedSecretSize]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:NonceSize]
	ct := ciphertext[NonceSize:]
	return aead.Open(nil, nonce, ct, nil)
}

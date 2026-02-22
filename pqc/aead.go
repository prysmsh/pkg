package pqc

import (
	"crypto/rand"
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
// Returns ErrDecryptionFailed if the ciphertext is tampered or authentication fails.
func DecryptPayload(sharedSecret [SharedSecretSize]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize {
		return nil, ErrDecryptionFailed
	}
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:NonceSize]
	ct := ciphertext[NonceSize:]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

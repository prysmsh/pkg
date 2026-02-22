package channel

import (
	"encoding/binary"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session provides post-handshake encrypted transport.
// It is safe for concurrent use; send and receive directions are independent.
type Session struct {
	sendKey [32]byte
	recvKey [32]byte

	sendCounter atomic.Uint64
	recvCounter atomic.Uint64

	sendMu sync.Mutex
	recvMu sync.Mutex
}

// Encrypt encrypts plaintext and returns the wire-format message:
//
//	[4 bytes] big-endian uint32 ciphertext length
//	[N bytes] ChaCha20-Poly1305 ciphertext (plaintext + 16-byte tag)
//
// Nonce: 4 zero bytes || 8-byte big-endian uint64 counter.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPayloadSize {
		return nil, ErrMaxPayloadSize
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	counter := s.sendCounter.Add(1) - 1
	if counter > nonceMax {
		return nil, ErrCounterExhausted
	}

	aead, err := chacha20poly1305.New(s.sendKey[:])
	if err != nil {
		return nil, err
	}

	nonce := makeNonce(counter)
	ct := aead.Seal(nil, nonce, plaintext, nil)

	// Wire format: 4-byte length prefix + ciphertext.
	out := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(out, uint32(len(ct)))
	copy(out[4:], ct)
	return out, nil
}

// Decrypt decrypts a wire-format message produced by Encrypt.
func (s *Session) Decrypt(msg []byte) ([]byte, error) {
	if len(msg) < 4 {
		return nil, ErrInvalidMessage
	}

	ctLen := binary.BigEndian.Uint32(msg[:4])
	if uint32(len(msg)-4) != ctLen {
		return nil, ErrInvalidMessage
	}
	ct := msg[4:]

	if len(ct) < chacha20poly1305.Overhead {
		return nil, ErrInvalidMessage
	}

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	counter := s.recvCounter.Add(1) - 1
	if counter > nonceMax {
		return nil, ErrCounterExhausted
	}

	aead, err := chacha20poly1305.New(s.recvKey[:])
	if err != nil {
		return nil, err
	}

	nonce := makeNonce(counter)
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return pt, nil
}

// makeNonce builds a 12-byte nonce: 4 zero bytes || 8-byte big-endian counter.
func makeNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

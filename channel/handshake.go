package channel

import (
	"crypto/sha256"
	"hash"
	"math"

	"github.com/prysmsh/pkg/kdf"
	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/pqc/sign"
	"golang.org/x/crypto/chacha20poly1305"
)

// Interfaces for testing and abstraction. The production types satisfy these.
type kemKeyPair interface {
	publicKeyBytes() ([]byte, error)
	decapsulate(ciphertext []byte) ([pqc.SharedSecretSize]byte, error)
}

type kemPublicKey interface {
	encapsulate() (ciphertext []byte, sharedSecret [pqc.SharedSecretSize]byte, err error)
}

type signingKeyPair interface {
	publicKeyBytes() ([]byte, error)
	sign(message []byte) ([]byte, error)
}

type transcriptHash interface {
	hash.Hash
}

// Production wrappers around pqc/sign types.
type realKEMKeyPair struct{ kp *pqc.HybridKeyPair }

func (r *realKEMKeyPair) publicKeyBytes() ([]byte, error) {
	return r.kp.PublicKey().MarshalBinary()
}
func (r *realKEMKeyPair) decapsulate(ct []byte) ([pqc.SharedSecretSize]byte, error) {
	return r.kp.Decapsulate(ct)
}

type realKEMPublicKey struct{ pk *pqc.HybridPublicKey }

func (r *realKEMPublicKey) encapsulate() ([]byte, [pqc.SharedSecretSize]byte, error) {
	return pqc.Encapsulate(r.pk)
}

type realSigningKeyPair struct{ kp *sign.HybridSigningKeyPair }

func (r *realSigningKeyPair) publicKeyBytes() ([]byte, error) {
	return r.kp.PublicKey().MarshalBinary()
}
func (r *realSigningKeyPair) sign(msg []byte) ([]byte, error) {
	return r.kp.Sign(msg)
}

// NewInitiator creates a handshake state machine for the initiating party.
// peerStaticPub is the expected peer signing public key; pass nil for TOFU.
func NewInitiator(signingKey *sign.HybridSigningKeyPair, peerStaticPub *sign.HybridPublicKey) (*Handshake, error) {
	eph, err := pqc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Handshake{
		isInitiator:    true,
		localEphemeral: &realKEMKeyPair{eph},
		localSigning:   &realSigningKeyPair{signingKey},
		peerStaticPub:  peerStaticPub,
		transcript:     sha256.New(),
	}, nil
}

// NewResponder creates a handshake state machine for the responding party.
func NewResponder(signingKey *sign.HybridSigningKeyPair) (*Handshake, error) {
	eph, err := pqc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Handshake{
		isInitiator:    false,
		localEphemeral: &realKEMKeyPair{eph},
		localSigning:   &realSigningKeyPair{signingKey},
		transcript:     sha256.New(),
	}, nil
}

// WriteMessage produces the next handshake message to send.
// The payload parameter is reserved for future use and should be nil.
func (h *Handshake) WriteMessage(payload []byte) ([]byte, error) {
	if h.session != nil {
		return nil, ErrHandshakeAlready
	}
	if h.isInitiator {
		switch h.step {
		case 0:
			return h.writeMsg1()
		case 2:
			return h.writeMsg3()
		default:
			return nil, ErrUnexpectedMessage
		}
	}
	// Responder.
	if h.step == 1 {
		return h.writeMsg2()
	}
	return nil, ErrUnexpectedMessage
}

// ReadMessage processes an incoming handshake message.
// Returns nil payload on success; the return slot is reserved for future use.
func (h *Handshake) ReadMessage(msg []byte) ([]byte, error) {
	if h.session != nil {
		return nil, ErrHandshakeAlready
	}
	if h.isInitiator {
		if h.step == 1 {
			return nil, h.readMsg2(msg)
		}
		return nil, ErrUnexpectedMessage
	}
	// Responder.
	switch h.step {
	case 0:
		return nil, h.readMsg1(msg)
	case 2:
		return nil, h.readMsg3(msg)
	default:
		return nil, ErrUnexpectedMessage
	}
}

// --- msg1: initiator ephemeral public key ---

func (h *Handshake) writeMsg1() ([]byte, error) {
	pub, err := h.localEphemeral.publicKeyBytes()
	if err != nil {
		return nil, err
	}
	h.transcript.Write(pub)
	h.step = 1
	return pub, nil
}

func (h *Handshake) readMsg1(msg []byte) error {
	pk, err := pqc.UnmarshalPublicKey(msg)
	if err != nil {
		return ErrInvalidMessage
	}
	h.remoteEphemeral = &realKEMPublicKey{pk}
	h.transcript.Write(msg)
	h.step = 1
	return nil
}

// --- msg2: responder ephemeral pub + KEM ciphertext + encrypted identity ---

func (h *Handshake) writeMsg2() ([]byte, error) {
	// Responder's ephemeral public key.
	ephPub, err := h.localEphemeral.publicKeyBytes()
	if err != nil {
		return nil, err
	}

	// KEM encapsulate to initiator's ephemeral.
	ct, ss1, err := h.remoteEphemeral.encapsulate()
	if err != nil {
		return nil, err
	}

	// Update transcript with non-encrypted prefix.
	h.transcript.Write(ephPub)
	h.transcript.Write(ct)

	// Derive chaining key and temp encryption key.
	h.ck1, err = kdf.HKDF(ss1[:], nil, []byte("channel-ck-1"), 32)
	if err != nil {
		return nil, err
	}
	tempKey1, err := kdf.HKDF(h.ck1, nil, []byte("channel-enc-1"), 32)
	if err != nil {
		return nil, err
	}

	// Build and encrypt identity payload: signing pubkey || signature.
	transcriptHash := h.transcript.Sum(nil)
	sigPub, err := h.localSigning.publicKeyBytes()
	if err != nil {
		return nil, err
	}
	sig, err := h.localSigning.sign(transcriptHash)
	if err != nil {
		return nil, err
	}
	identityPayload := append(sigPub, sig...)
	encPayload, err := encryptHandshake(tempKey1, identityPayload)
	if err != nil {
		return nil, err
	}

	// Update transcript with encrypted payload.
	h.transcript.Write(encPayload)

	// Assemble msg2.
	msg := make([]byte, 0, len(ephPub)+len(ct)+len(encPayload))
	msg = append(msg, ephPub...)
	msg = append(msg, ct...)
	msg = append(msg, encPayload...)
	h.step = 2
	return msg, nil
}

func (h *Handshake) readMsg2(msg []byte) error {
	// Parse msg2: resp ephemeral pub | KEM ciphertext | encrypted payload.
	ephSize := pqc.HybridPublicKeySize
	ctSize := pqc.HybridCiphertextSize
	minSize := ephSize + ctSize + chacha20poly1305.Overhead
	if len(msg) < minSize {
		return ErrInvalidMessage
	}

	ephPubBytes := msg[:ephSize]
	ctBytes := msg[ephSize : ephSize+ctSize]
	encPayload := msg[ephSize+ctSize:]

	// Parse responder's ephemeral public key.
	respEphPub, err := pqc.UnmarshalPublicKey(ephPubBytes)
	if err != nil {
		return ErrInvalidMessage
	}
	h.remoteEphemeral = &realKEMPublicKey{respEphPub}

	// Update transcript with non-encrypted prefix.
	h.transcript.Write(ephPubBytes)
	h.transcript.Write(ctBytes)

	// Decapsulate to get shared secret.
	ss1, err := h.localEphemeral.decapsulate(ctBytes)
	if err != nil {
		return ErrDecryptionFailed
	}

	// Derive chaining key and temp encryption key.
	h.ck1, err = kdf.HKDF(ss1[:], nil, []byte("channel-ck-1"), 32)
	if err != nil {
		return err
	}
	tempKey1, err := kdf.HKDF(h.ck1, nil, []byte("channel-enc-1"), 32)
	if err != nil {
		return err
	}

	// Decrypt identity payload.
	transcriptHash := h.transcript.Sum(nil)
	identityPayload, err := decryptHandshake(tempKey1, encPayload)
	if err != nil {
		return ErrDecryptionFailed
	}

	// Parse: signing pubkey || signature.
	sigPubSize := sign.HybridPublicKeySize
	sigSize := sign.HybridSignatureSize
	if len(identityPayload) != sigPubSize+sigSize {
		return ErrInvalidMessage
	}
	peerPub, err := sign.UnmarshalPublicKey(identityPayload[:sigPubSize])
	if err != nil {
		return ErrInvalidMessage
	}

	// Verify signature.
	if !sign.Verify(peerPub, transcriptHash, identityPayload[sigPubSize:]) {
		return ErrAuthenticationFailed
	}

	// If we have an expected peer identity, check it.
	if h.peerStaticPub != nil {
		expected, err := h.peerStaticPub.MarshalBinary()
		if err != nil {
			return err
		}
		got, err := peerPub.MarshalBinary()
		if err != nil {
			return err
		}
		if !constantTimeEqual(expected, got) {
			return ErrAuthenticationFailed
		}
	}
	h.peerIdentity = peerPub

	// Update transcript with encrypted payload.
	h.transcript.Write(encPayload)
	h.step = 2
	return nil
}

// --- msg3: initiator KEM ciphertext + encrypted identity ---

func (h *Handshake) writeMsg3() ([]byte, error) {
	// KEM encapsulate to responder's ephemeral.
	ct, ss2, err := h.remoteEphemeral.encapsulate()
	if err != nil {
		return nil, err
	}

	// Update transcript with non-encrypted prefix.
	h.transcript.Write(ct)

	// Derive ck2 and tempKey2.
	ck1ss2 := append(h.ck1, ss2[:]...)
	ck2, err := kdf.HKDF(ck1ss2, nil, []byte("channel-ck-2"), 32)
	if err != nil {
		return nil, err
	}
	tempKey2, err := kdf.HKDF(ck2, nil, []byte("channel-enc-2"), 32)
	if err != nil {
		return nil, err
	}

	// Build and encrypt identity payload.
	transcriptHash := h.transcript.Sum(nil)
	sigPub, err := h.localSigning.publicKeyBytes()
	if err != nil {
		return nil, err
	}
	sig, err := h.localSigning.sign(transcriptHash)
	if err != nil {
		return nil, err
	}
	identityPayload := append(sigPub, sig...)
	encPayload, err := encryptHandshake(tempKey2, identityPayload)
	if err != nil {
		return nil, err
	}

	// Update transcript with encrypted payload.
	h.transcript.Write(encPayload)

	// Derive session keys.
	session, err := deriveSession(ck2, true)
	if err != nil {
		return nil, err
	}
	h.session = session

	// Assemble msg3.
	msg := make([]byte, 0, len(ct)+len(encPayload))
	msg = append(msg, ct...)
	msg = append(msg, encPayload...)
	h.step = 3
	return msg, nil
}

func (h *Handshake) readMsg3(msg []byte) error {
	// Parse msg3: KEM ciphertext | encrypted payload.
	ctSize := pqc.HybridCiphertextSize
	if len(msg) < ctSize+chacha20poly1305.Overhead {
		return ErrInvalidMessage
	}

	ctBytes := msg[:ctSize]
	encPayload := msg[ctSize:]

	// Update transcript with non-encrypted prefix.
	h.transcript.Write(ctBytes)

	// Decapsulate to get shared secret.
	ss2, err := h.localEphemeral.decapsulate(ctBytes)
	if err != nil {
		return ErrDecryptionFailed
	}

	// Derive ck2 and tempKey2.
	ck1ss2 := append(h.ck1, ss2[:]...)
	ck2, err := kdf.HKDF(ck1ss2, nil, []byte("channel-ck-2"), 32)
	if err != nil {
		return err
	}
	tempKey2, err := kdf.HKDF(ck2, nil, []byte("channel-enc-2"), 32)
	if err != nil {
		return err
	}

	// Decrypt identity payload.
	transcriptHash := h.transcript.Sum(nil)
	identityPayload, err := decryptHandshake(tempKey2, encPayload)
	if err != nil {
		return ErrDecryptionFailed
	}

	// Parse: signing pubkey || signature.
	sigPubSize := sign.HybridPublicKeySize
	sigSize := sign.HybridSignatureSize
	if len(identityPayload) != sigPubSize+sigSize {
		return ErrInvalidMessage
	}
	peerPub, err := sign.UnmarshalPublicKey(identityPayload[:sigPubSize])
	if err != nil {
		return ErrInvalidMessage
	}

	// Verify signature.
	if !sign.Verify(peerPub, transcriptHash, identityPayload[sigPubSize:]) {
		return ErrAuthenticationFailed
	}
	h.peerIdentity = peerPub

	// Update transcript with encrypted payload.
	h.transcript.Write(encPayload)

	// Derive session keys.
	session, err := deriveSession(ck2, false)
	if err != nil {
		return err
	}
	h.session = session
	h.step = 3
	return nil
}

// --- helpers ---

func deriveSession(ck2 []byte, isInitiator bool) (*Session, error) {
	sessionBytes, err := kdf.HKDF(ck2, nil, []byte("channel-session"), 64)
	if err != nil {
		return nil, err
	}
	s := &Session{}
	if isInitiator {
		copy(s.sendKey[:], sessionBytes[:32])
		copy(s.recvKey[:], sessionBytes[32:])
	} else {
		copy(s.sendKey[:], sessionBytes[32:])
		copy(s.recvKey[:], sessionBytes[:32])
	}
	return s, nil
}

func encryptHandshake(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize) // all zeros, key used once
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func decryptHandshake(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	pt, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// nonceMax is the maximum counter value before ErrCounterExhausted.
const nonceMax = uint64(math.MaxUint64) - 1

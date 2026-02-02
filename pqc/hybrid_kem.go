// Package pqc provides post-quantum cryptographic primitives for DERP and mesh.
// Implements hybrid key encapsulation (X25519 + Kyber768) for quantum-resistant key exchange.
package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
)

const (
	X25519KeySize        = 32
	HybridPublicKeySize  = X25519KeySize + kyber768.PublicKeySize
	HybridSecretKeySize  = X25519KeySize + kyber768.PrivateKeySize
	HybridCiphertextSize = X25519KeySize + kyber768.CiphertextSize
	SharedSecretSize     = 32
)

type HybridKeyPair struct {
	X25519Public  [X25519KeySize]byte
	X25519Private [X25519KeySize]byte
	KyberPublic   kem.PublicKey
	KyberPrivate  kem.PrivateKey
}

type HybridPublicKey struct {
	X25519Public [X25519KeySize]byte
	KyberPublic  kem.PublicKey
}

func GenerateKeyPair() (*HybridKeyPair, error) {
	kp := &HybridKeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.X25519Private[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&kp.X25519Public, &kp.X25519Private)
	kyberScheme := kyber768.Scheme()
	pub, priv, err := kyberScheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	kp.KyberPublic = pub
	kp.KyberPrivate = priv
	return kp, nil
}

func (kp *HybridKeyPair) PublicKey() *HybridPublicKey {
	return &HybridPublicKey{
		X25519Public: kp.X25519Public,
		KyberPublic:  kp.KyberPublic,
	}
}

func (pk *HybridPublicKey) MarshalBinary() ([]byte, error) {
	kyberPubBytes, err := pk.KyberPublic.MarshalBinary()
	if err != nil {
		return nil, err
	}
	result := make([]byte, HybridPublicKeySize)
	copy(result[:X25519KeySize], pk.X25519Public[:])
	copy(result[X25519KeySize:], kyberPubBytes)
	return result, nil
}

func UnmarshalPublicKey(data []byte) (*HybridPublicKey, error) {
	if len(data) != HybridPublicKeySize {
		return nil, errors.New("invalid public key size")
	}
	pk := &HybridPublicKey{}
	copy(pk.X25519Public[:], data[:X25519KeySize])
	kyberScheme := kyber768.Scheme()
	kyberPub, err := kyberScheme.UnmarshalBinaryPublicKey(data[X25519KeySize:])
	if err != nil {
		return nil, err
	}
	pk.KyberPublic = kyberPub
	return pk, nil
}

func Encapsulate(recipientPub *HybridPublicKey) (ciphertext []byte, sharedSecret [SharedSecretSize]byte, err error) {
	var ephemeralPrivate, ephemeralPublic [X25519KeySize]byte
	if _, err = io.ReadFull(rand.Reader, ephemeralPrivate[:]); err != nil {
		return nil, sharedSecret, err
	}
	curve25519.ScalarBaseMult(&ephemeralPublic, &ephemeralPrivate)
	var x25519Shared [X25519KeySize]byte
	curve25519.ScalarMult(&x25519Shared, &ephemeralPrivate, &recipientPub.X25519Public)
	kyberScheme := kyber768.Scheme()
	kyberCiphertext, kyberShared, err := kyberScheme.Encapsulate(recipientPub.KyberPublic)
	if err != nil {
		return nil, sharedSecret, err
	}
	ciphertext = make([]byte, HybridCiphertextSize)
	copy(ciphertext[:X25519KeySize], ephemeralPublic[:])
	copy(ciphertext[X25519KeySize:], kyberCiphertext)
	h := sha256.New()
	h.Write(x25519Shared[:])
	h.Write(kyberShared)
	copy(sharedSecret[:], h.Sum(nil))
	return ciphertext, sharedSecret, nil
}

func (kp *HybridKeyPair) Decapsulate(ciphertext []byte) ([SharedSecretSize]byte, error) {
	var sharedSecret [SharedSecretSize]byte
	if len(ciphertext) != HybridCiphertextSize {
		return sharedSecret, errors.New("invalid ciphertext size")
	}
	var ephemeralPublic [X25519KeySize]byte
	copy(ephemeralPublic[:], ciphertext[:X25519KeySize])
	var x25519Shared [X25519KeySize]byte
	curve25519.ScalarMult(&x25519Shared, &kp.X25519Private, &ephemeralPublic)
	kyberScheme := kyber768.Scheme()
	kyberShared, err := kyberScheme.Decapsulate(kp.KyberPrivate, ciphertext[X25519KeySize:])
	if err != nil {
		return sharedSecret, err
	}
	h := sha256.New()
	h.Write(x25519Shared[:])
	h.Write(kyberShared)
	copy(sharedSecret[:], h.Sum(nil))
	return sharedSecret, nil
}

// MarshalKeyPair serializes the key pair for persistent storage.
func (kp *HybridKeyPair) MarshalKeyPair() ([]byte, error) {
	kyberPriv, err := kp.KyberPrivate.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, X25519KeySize+len(kyberPriv))
	out = append(out, kp.X25519Private[:]...)
	out = append(out, kyberPriv...)
	return out, nil
}

// UnmarshalKeyPair deserializes a key pair from storage.
func UnmarshalKeyPair(data []byte) (*HybridKeyPair, error) {
	if len(data) < X25519KeySize {
		return nil, errors.New("hybrid key data too short")
	}
	kp := &HybridKeyPair{}
	copy(kp.X25519Private[:], data[:X25519KeySize])
	curve25519.ScalarBaseMult(&kp.X25519Public, &kp.X25519Private)
	kyberScheme := kyber768.Scheme()
	kyberPriv, err := kyberScheme.UnmarshalBinaryPrivateKey(data[X25519KeySize:])
	if err != nil {
		return nil, err
	}
	kp.KyberPrivate = kyberPriv
	kp.KyberPublic = kyberPriv.Public()
	return kp, nil
}

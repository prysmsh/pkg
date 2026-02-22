// Package sign provides hybrid post-quantum signatures (Ed25519 + Dilithium3).
// Both signatures are required for verification, providing security against
// classical and quantum adversaries.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/hkdf"
)

const (
	Ed25519PublicKeySize  = 32
	Ed25519PrivateKeySize = 64
	Ed25519SignatureSize  = 64
)

// Sentinel errors for programmatic error handling.
var (
	ErrSeedTooShort        = errors.New("sign: seed too short")
	ErrInvalidPublicKeySize  = errors.New("sign: invalid hybrid public key size")
	ErrInvalidPrivateKeySize = errors.New("sign: invalid hybrid private key size")
)

var (
	dilithiumScheme = mode3.Scheme()
	DilithiumPubSize = dilithiumScheme.PublicKeySize()
	DilithiumPrivSize = dilithiumScheme.PrivateKeySize()
	DilithiumSigSize  = dilithiumScheme.SignatureSize()

	// HybridPublicKeySize is Ed25519 (32) + Dilithium3 public key.
	HybridPublicKeySize = Ed25519PublicKeySize + DilithiumPubSize
	// HybridPrivateKeySize is Ed25519 (64) + Dilithium3 private key.
	HybridPrivateKeySize = Ed25519PrivateKeySize + DilithiumPrivSize
	// HybridSignatureSize is Ed25519 (64) + Dilithium3 signature.
	HybridSignatureSize = Ed25519SignatureSize + DilithiumSigSize
)

// HybridSigningKeyPair holds both Ed25519 and Dilithium3 key material.
type HybridSigningKeyPair struct {
	ed25519Pub  ed25519.PublicKey
	ed25519Priv ed25519.PrivateKey
	dilithiumPub  sign.PublicKey
	dilithiumPriv sign.PrivateKey
}

// HybridPublicKey is the public part of a hybrid signing key pair.
type HybridPublicKey struct {
	Ed25519Public  [Ed25519PublicKeySize]byte
	DilithiumPublic sign.PublicKey
}

// GenerateSigningKeyPair creates a new hybrid Ed25519 + Dilithium3 key pair.
func GenerateSigningKeyPair() (*HybridSigningKeyPair, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dilPub, dilPriv, err := dilithiumScheme.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &HybridSigningKeyPair{
		ed25519Pub:     edPub,
		ed25519Priv:    edPriv,
		dilithiumPub:   dilPub,
		dilithiumPriv:  dilPriv,
	}, nil
}

// GenerateSigningKeyPairFromSeed creates a deterministic key pair from a seed.
// Seed must be at least dilithiumScheme.SeedSize() bytes (typically 32).
// The Ed25519 seed is derived via HKDF-SHA256 for proper entropy regardless of input length.
func GenerateSigningKeyPairFromSeed(seed []byte) (*HybridSigningKeyPair, error) {
	seedSize := dilithiumScheme.SeedSize()
	if len(seed) < seedSize {
		return nil, ErrSeedTooShort
	}
	// Derive a 32-byte Ed25519 seed via HKDF for proper entropy handling.
	edSeed := make([]byte, 32)
	r := hkdf.New(sha256.New, seed, nil, []byte("pqc-sign-ed25519"))
	if _, err := r.Read(edSeed); err != nil {
		return nil, err
	}
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	edPub := edPriv.Public().(ed25519.PublicKey)
	dilPub, dilPriv := dilithiumScheme.DeriveKey(seed[:seedSize])
	return &HybridSigningKeyPair{
		ed25519Pub:    edPub,
		ed25519Priv:   edPriv,
		dilithiumPub:  dilPub,
		dilithiumPriv: dilPriv,
	}, nil
}

// PublicKey returns the hybrid public key.
func (kp *HybridSigningKeyPair) PublicKey() *HybridPublicKey {
	pk := &HybridPublicKey{}
	copy(pk.Ed25519Public[:], kp.ed25519Pub)
	pk.DilithiumPublic = kp.dilithiumPub
	return pk
}

// Sign signs the message with both Ed25519 and Dilithium3.
// Signature format: ed25519_sig (64 bytes) || dilithium_sig.
func (kp *HybridSigningKeyPair) Sign(message []byte) ([]byte, error) {
	edSig := ed25519.Sign(kp.ed25519Priv, message)
	dilSig := dilithiumScheme.Sign(kp.dilithiumPriv, message, nil)
	sig := make([]byte, HybridSignatureSize)
	copy(sig[:Ed25519SignatureSize], edSig)
	copy(sig[Ed25519SignatureSize:], dilSig)
	return sig, nil
}

// Verify checks both Ed25519 and Dilithium3 signatures.
// Returns true only if both verify.
func Verify(publicKey *HybridPublicKey, message, signature []byte) bool {
	if len(signature) != HybridSignatureSize {
		return false
	}
	if !ed25519.Verify(publicKey.Ed25519Public[:], message, signature[:Ed25519SignatureSize]) {
		return false
	}
	if !dilithiumScheme.Verify(publicKey.DilithiumPublic, message, signature[Ed25519SignatureSize:], nil) {
		return false
	}
	return true
}

// MarshalPublicKey serializes the hybrid public key.
func (pk *HybridPublicKey) MarshalBinary() ([]byte, error) {
	dilBytes, err := pk.DilithiumPublic.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, HybridPublicKeySize)
	copy(out[:Ed25519PublicKeySize], pk.Ed25519Public[:])
	copy(out[Ed25519PublicKeySize:], dilBytes)
	return out, nil
}

// UnmarshalPublicKey deserializes a hybrid public key.
func UnmarshalPublicKey(data []byte) (*HybridPublicKey, error) {
	if len(data) != HybridPublicKeySize {
		return nil, ErrInvalidPublicKeySize
	}
	pk := &HybridPublicKey{}
	copy(pk.Ed25519Public[:], data[:Ed25519PublicKeySize])
	dilPub, err := dilithiumScheme.UnmarshalBinaryPublicKey(data[Ed25519PublicKeySize:])
	if err != nil {
		return nil, err
	}
	pk.DilithiumPublic = dilPub
	return pk, nil
}

// MarshalKeyPair serializes the private key for storage.
func (kp *HybridSigningKeyPair) MarshalKeyPair() ([]byte, error) {
	dilBytes, err := kp.dilithiumPriv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, HybridPrivateKeySize)
	copy(out[:Ed25519PrivateKeySize], kp.ed25519Priv)
	copy(out[Ed25519PrivateKeySize:], dilBytes)
	return out, nil
}

// UnmarshalKeyPair deserializes a key pair from storage.
func UnmarshalKeyPair(data []byte) (*HybridSigningKeyPair, error) {
	if len(data) != HybridPrivateKeySize {
		return nil, ErrInvalidPrivateKeySize
	}
	kp := &HybridSigningKeyPair{}
	kp.ed25519Priv = make([]byte, Ed25519PrivateKeySize)
	copy(kp.ed25519Priv, data[:Ed25519PrivateKeySize])
	kp.ed25519Pub = kp.ed25519Priv.Public().(ed25519.PublicKey)
	dilPriv, err := dilithiumScheme.UnmarshalBinaryPrivateKey(data[Ed25519PrivateKeySize:])
	if err != nil {
		return nil, err
	}
	kp.dilithiumPriv = dilPriv
	kp.dilithiumPub = dilPriv.Public().(sign.PublicKey)
	return kp, nil
}

package sign

import (
	"bytes"
	"testing"
)

func TestGenerateSigningKeyPair(t *testing.T) {
	kp, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pk := kp.PublicKey()
	msg := []byte("test message")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != HybridSignatureSize {
		t.Errorf("signature size: want %d, got %d", HybridSignatureSize, len(sig))
	}
	if !Verify(pk, msg, sig) {
		t.Error("Verify failed")
	}
}

func TestVerifyTampered(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	pk := kp.PublicKey()
	msg := []byte("test")
	sig, _ := kp.Sign(msg)
	if Verify(pk, []byte("wrong"), sig) {
		t.Error("Verify should fail for wrong message")
	}
	sig[0] ^= 0xff
	if Verify(pk, msg, sig) {
		t.Error("Verify should fail for tampered signature")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	pk := kp.PublicKey()

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkBytes) != HybridPublicKeySize {
		t.Errorf("public key size: want %d, got %d", HybridPublicKeySize, len(pkBytes))
	}
	pk2, err := UnmarshalPublicKey(pkBytes)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("verify marshal")
	sig, _ := kp.Sign(msg)
	if !Verify(pk2, msg, sig) {
		t.Error("Unmarshaled public key should verify")
	}

	kpBytes, err := kp.MarshalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := UnmarshalKeyPair(kpBytes)
	if err != nil {
		t.Fatal(err)
	}
	sig2, _ := kp2.Sign(msg)
	if !Verify(pk, msg, sig2) {
		t.Error("Unmarshaled key pair should sign and verify")
	}
}

func TestVerify_WrongSignatureSize(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	pk := kp.PublicKey()
	if Verify(pk, []byte("msg"), []byte("short")) {
		t.Error("Verify should fail for wrong signature size")
	}
}

func TestVerify_DilithiumTampered(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	pk := kp.PublicKey()
	msg := []byte("test")
	sig, _ := kp.Sign(msg)
	// Tamper only the Dilithium portion (leave Ed25519 intact)
	sig[Ed25519SignatureSize] ^= 0xff
	if Verify(pk, msg, sig) {
		t.Error("Verify should fail when Dilithium signature is tampered")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	kp1, _ := GenerateSigningKeyPair()
	kp2, _ := GenerateSigningKeyPair()
	msg := []byte("test")
	sig, _ := kp1.Sign(msg)
	if Verify(kp2.PublicKey(), msg, sig) {
		t.Error("Verify should fail with wrong key")
	}
}

func TestUnmarshalPublicKey_InvalidSize(t *testing.T) {
	_, err := UnmarshalPublicKey([]byte("short"))
	if err != ErrInvalidPublicKeySize {
		t.Errorf("expected ErrInvalidPublicKeySize, got %v", err)
	}
}

func TestUnmarshalKeyPair_InvalidSize(t *testing.T) {
	_, err := UnmarshalKeyPair([]byte("short"))
	if err != ErrInvalidPrivateKeySize {
		t.Errorf("expected ErrInvalidPrivateKeySize, got %v", err)
	}
}

func TestGenerateSigningKeyPairFromSeed_TooShort(t *testing.T) {
	_, err := GenerateSigningKeyPairFromSeed([]byte("short"))
	if err != ErrSeedTooShort {
		t.Errorf("expected ErrSeedTooShort, got %v", err)
	}
}

func TestGenerateFromSeed(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	kp1, err := GenerateSigningKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	kp2, _ := GenerateSigningKeyPairFromSeed(seed)
	if !bytes.Equal(kp1.PublicKey().Ed25519Public[:], kp2.PublicKey().Ed25519Public[:]) {
		t.Error("same seed should produce same Ed25519 key")
	}
}

func BenchmarkSign(b *testing.B) {
	kp, _ := GenerateSigningKeyPair()
	msg := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = kp.Sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	kp, _ := GenerateSigningKeyPair()
	pk := kp.PublicKey()
	msg := []byte("benchmark message")
	sig, _ := kp.Sign(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pk, msg, sig)
	}
}

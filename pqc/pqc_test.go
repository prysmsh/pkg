package pqc

import (
	"bytes"
	"errors"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp == nil {
		t.Fatal("key pair is nil")
	}
	// Verify public key derives from private
	pub := kp.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey() returned nil")
	}
	if len(pub.X25519Public) != X25519KeySize {
		t.Errorf("X25519Public size = %d, want %d", len(pub.X25519Public), X25519KeySize)
	}
}

func TestEncapsulateDecapsulate_RoundTrip(t *testing.T) {
	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub := recipient.PublicKey()

	ciphertext, senderSecret, err := Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ciphertext) != HybridCiphertextSize {
		t.Errorf("ciphertext size = %d, want %d", len(ciphertext), HybridCiphertextSize)
	}
	if len(senderSecret) != SharedSecretSize {
		t.Errorf("shared secret size = %d, want %d", len(senderSecret), SharedSecretSize)
	}

	recipientSecret, err := recipient.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(senderSecret[:], recipientSecret[:]) {
		t.Error("shared secrets do not match")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	pub := kp.PublicKey()
	_, sharedSecret, _ := Encapsulate(pub)

	plaintext := []byte("hello, post-quantum world")
	ciphertext, err := EncryptPayload(sharedSecret, plaintext)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if len(ciphertext) < NonceSize+len(plaintext) {
		t.Errorf("ciphertext too short: %d", len(ciphertext))
	}

	decrypted, err := DecryptPayload(sharedSecret, ciphertext)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, sharedSecret, _ := Encapsulate(kp.PublicKey())

	ct, err := EncryptPayload(sharedSecret, nil)
	if err != nil {
		t.Fatalf("EncryptPayload(nil): %v", err)
	}
	pt, err := DecryptPayload(sharedSecret, ct)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if pt != nil {
		t.Errorf("decrypted nil plaintext = %v, want nil", pt)
	}
}

func TestPublicKeyMarshalUnmarshal(t *testing.T) {
	kp, _ := GenerateKeyPair()
	pub := kp.PublicKey()

	data, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(data) != HybridPublicKeySize {
		t.Errorf("marshaled size = %d, want %d", len(data), HybridPublicKeySize)
	}

	restored, err := UnmarshalPublicKey(data)
	if err != nil {
		t.Fatalf("UnmarshalPublicKey: %v", err)
	}
	data2, _ := restored.MarshalBinary()
	if !bytes.Equal(data, data2) {
		t.Error("marshal(unmarshal(data)) != data")
	}
}

func TestUnmarshalPublicKey_InvalidSize(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, HybridPublicKeySize-1)},
		{"too long", make([]byte, HybridPublicKeySize+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalPublicKey(tt.data)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestDecapsulate_InvalidCiphertextSize(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := kp.Decapsulate(nil)
	if err == nil {
		t.Error("Decapsulate(nil): expected error")
	}
	_, err = kp.Decapsulate(make([]byte, HybridCiphertextSize-1))
	if err == nil {
		t.Error("Decapsulate(short): expected error")
	}
}

func TestDecryptPayload_TooShort(t *testing.T) {
	var secret [SharedSecretSize]byte
	_, err := DecryptPayload(secret, nil)
	if err == nil {
		t.Error("DecryptPayload(nil): expected error")
	}
	_, err = DecryptPayload(secret, make([]byte, NonceSize-1))
	if err == nil {
		t.Error("DecryptPayload(short): expected error")
	}
}

func TestDecryptPayload_TamperedCiphertext(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, sharedSecret, _ := Encapsulate(kp.PublicKey())
	ct, _ := EncryptPayload(sharedSecret, []byte("secret"))

	// Tamper with ciphertext
	ct[NonceSize] ^= 0xff

	_, err := DecryptPayload(sharedSecret, ct)
	if err == nil {
		t.Error("DecryptPayload(tampered): expected authentication failure")
	}
	if err != nil && !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestKeyPairMarshalUnmarshal(t *testing.T) {
	kp, _ := GenerateKeyPair()
	data, err := kp.MarshalKeyPair()
	if err != nil {
		t.Fatalf("MarshalKeyPair: %v", err)
	}

	restored, err := UnmarshalKeyPair(data)
	if err != nil {
		t.Fatalf("UnmarshalKeyPair: %v", err)
	}

	// Encapsulate with original, decapsulate with restored
	pub := kp.PublicKey()
	ct, _, _ := Encapsulate(pub)
	_, err = restored.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate with restored key: %v", err)
	}
}

func TestUnmarshalKeyPair_Invalid(t *testing.T) {
	_, err := UnmarshalKeyPair(nil)
	if err == nil {
		t.Error("UnmarshalKeyPair(nil): expected error")
	}
	_, err = UnmarshalKeyPair(make([]byte, X25519KeySize-1))
	if err == nil {
		t.Error("UnmarshalKeyPair(short): expected error")
	}
}

func ExampleEncapsulate() {
	recipient, _ := GenerateKeyPair()
	pub := recipient.PublicKey()
	ciphertext, sharedSecret, err := Encapsulate(pub)
	if err != nil {
		return
	}
	_ = ciphertext
	_ = sharedSecret
}

func ExampleEncryptPayload() {
	kp, _ := GenerateKeyPair()
	_, secret, _ := Encapsulate(kp.PublicKey())
	plaintext := []byte("secret message")
	ciphertext, err := EncryptPayload(secret, plaintext)
	if err != nil {
		return
	}
	_ = ciphertext
}

func BenchmarkEncapsulateDecapsulate(b *testing.B) {
	kp, _ := GenerateKeyPair()
	pub := kp.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _, _ := Encapsulate(pub)
		kp.Decapsulate(ct)
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	kp, _ := GenerateKeyPair()
	_, secret, _ := Encapsulate(kp.PublicKey())
	plaintext := []byte("benchmark payload")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _ := EncryptPayload(secret, plaintext)
		DecryptPayload(secret, ct)
	}
}

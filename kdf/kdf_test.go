package kdf

import (
	"bytes"
	"testing"
)

func TestHKDF(t *testing.T) {
	secret := []byte("master-secret-key")
	salt := []byte("salt")
	info := []byte("agent-session")

	out, err := HKDF(secret, salt, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(out))
	}
	// Same inputs = same output
	out2, _ := HKDF(secret, salt, info, 32)
	if !bytes.Equal(out, out2) {
		t.Error("deterministic HKDF should produce same output")
	}
	// Different info = different output
	out3, _ := HKDF(secret, salt, []byte("other"), 32)
	if bytes.Equal(out, out3) {
		t.Error("different info should produce different output")
	}

	_, err = HKDF(secret, salt, info, 0)
	if err == nil {
		t.Error("size 0 should error")
	}
	_, err = HKDF(nil, salt, info, 32)
	if err == nil {
		t.Error("empty secret should error")
	}
}

func TestArgon2id(t *testing.T) {
	password := []byte("bootstrap-password")
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	out, err := Argon2id(password, salt, 1, 64*1024, 4, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(out))
	}
	// Same inputs = same output
	out2, _ := Argon2id(password, salt, 1, 64*1024, 4, 32)
	if !bytes.Equal(out, out2) {
		t.Error("deterministic Argon2id should produce same output")
	}

	_, err = Argon2id(nil, salt, 1, 64*1024, 4, 32)
	if err == nil {
		t.Error("empty password should error")
	}
	_, err = Argon2id(password, salt[:4], 1, 64*1024, 4, 32)
	if err == nil {
		t.Error("short salt should error")
	}
}

func TestDefaultArgon2idParams(t *testing.T) {
	p := DefaultArgon2idParams()
	if p.Time != 3 {
		t.Errorf("Time = %d, want 3", p.Time)
	}
	if p.Memory != 64*1024 {
		t.Errorf("Memory = %d, want %d", p.Memory, 64*1024)
	}
	if p.Threads != 4 {
		t.Errorf("Threads = %d, want 4", p.Threads)
	}
	if p.KeyLen != 32 {
		t.Errorf("KeyLen = %d, want 32", p.KeyLen)
	}
}

func TestArgon2id_InvalidKeyLen(t *testing.T) {
	salt := make([]byte, 16)
	_, err := Argon2id([]byte("pass"), salt, 1, 64*1024, 4, 0)
	if err == nil {
		t.Error("keyLen 0 should error")
	}
	_, err = Argon2id([]byte("pass"), salt, 1, 64*1024, 4, 65)
	if err == nil {
		t.Error("keyLen > 64 should error")
	}
}

func TestArgon2id_ThreadsZeroFallback(t *testing.T) {
	salt := make([]byte, 16)
	out, err := Argon2id([]byte("pass"), salt, 1, 64*1024, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(out))
	}
}

func TestHKDF_MaxSize(t *testing.T) {
	secret := []byte("secret")
	_, err := HKDF(secret, nil, nil, 255*32)
	if err != nil {
		t.Fatalf("max size should work: %v", err)
	}
	_, err = HKDF(secret, nil, nil, 255*32+1)
	if err == nil {
		t.Error("over max size should error")
	}
}

func BenchmarkHKDF(b *testing.B) {
	secret := []byte("master-secret-key-32-bytes-long")
	salt := []byte("salt")
	info := []byte("agent-session")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HKDF(secret, salt, info, 32)
	}
}

func BenchmarkArgon2id(b *testing.B) {
	password := []byte("bootstrap-password")
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Argon2id(password, salt, 1, 64*1024, 4, 32)
	}
}

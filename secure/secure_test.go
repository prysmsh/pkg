package secure

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestConstantTimeEqual_Equal(t *testing.T) {
	a := []byte("secret-token")
	b := []byte("secret-token")
	if !ConstantTimeEqual(a, b) {
		t.Error("expected equal slices to return true")
	}
}

func TestConstantTimeEqual_Unequal(t *testing.T) {
	a := []byte("secret-token")
	b := []byte("secret-token!")
	if ConstantTimeEqual(a, b) {
		t.Error("expected unequal slices to return false")
	}
}

func TestConstantTimeEqual_Empty(t *testing.T) {
	if !ConstantTimeEqual(nil, nil) {
		t.Error("nil == nil should be true")
	}
	if ConstantTimeEqual([]byte{}, []byte{0}) {
		t.Error("empty vs single byte should be false")
	}
}

func TestConstantTimeEqual_LengthMismatch(t *testing.T) {
	a := []byte("short")
	b := []byte("longer")
	if ConstantTimeEqual(a, b) {
		t.Error("different lengths should return false")
	}
}

func TestRandomBytes(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("len = %d, want 32", len(b))
	}
	// Check we get different values on successive calls
	b2, _ := RandomBytes(32)
	if bytes.Equal(b, b2) {
		t.Error("expected different random bytes")
	}
}

func TestRandomBytes_Zero(t *testing.T) {
	b, err := RandomBytes(0)
	if err != nil {
		t.Fatalf("RandomBytes(0): %v", err)
	}
	if b != nil {
		t.Errorf("expected nil for n=0, got %v", b)
	}
}

func TestRandomHex(t *testing.T) {
	s, err := RandomHex(16)
	if err != nil {
		t.Fatalf("RandomHex: %v", err)
	}
	if len(s) != 32 {
		t.Errorf("hex string len = %d, want 32 (16 bytes)", len(s))
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
	if len(decoded) != 16 {
		t.Errorf("decoded len = %d, want 16", len(decoded))
	}
}

func TestRandomHex_Uniqueness(t *testing.T) {
	s1, _ := RandomHex(32)
	s2, _ := RandomHex(32)
	if s1 == s2 {
		t.Error("expected different hex strings")
	}
}

func ExampleConstantTimeEqual() {
	token := []byte("secret-api-key")
	userInput := []byte("secret-api-key")
	if !ConstantTimeEqual(token, userInput) {
		// Invalid token - reject request
		return
	}
	// Token valid, proceed
}

func ExampleRandomHex() {
	id, err := RandomHex(32)
	if err != nil {
		return
	}
	_ = id // use as session ID, request ID, etc.
}

func ExampleRandomBytes() {
	b, err := RandomBytes(16)
	if err != nil {
		return
	}
	_ = b // use as nonce, key material, etc.
}

package util

import (
	"testing"
)

func TestSecureCompare(t *testing.T) {
	a := []byte("secret-token-123")
	b := []byte("secret-token-123")
	c := []byte("secret-token-456")

	if !SecureCompare(a, b) {
		t.Error("identical slices should compare equal")
	}
	if SecureCompare(a, c) {
		t.Error("different slices should not compare equal")
	}
	if SecureCompare(a, a[:5]) {
		t.Error("different length slices should not compare equal")
	}
	if SecureCompare([]byte{}, []byte{}) {
		// Empty slices: ConstantTimeCompare returns 1 for two empty slices
		// Verify behavior
	}
}

func TestSecureToken(t *testing.T) {
	tok, err := SecureToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 {
		t.Errorf("32 bytes hex = 64 chars, got %d", len(tok))
	}
	// Different calls should produce different tokens
	tok2, _ := SecureToken(32)
	if tok == tok2 {
		t.Error("tokens should be unique")
	}

	_, err = SecureToken(0)
	if err == nil {
		t.Error("size 0 should error")
	}
	_, err = SecureToken(65537)
	if err == nil {
		t.Error("size > 65536 should error")
	}
}

func TestSecureToken_Boundary(t *testing.T) {
	tok, err := SecureToken(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 2 {
		t.Errorf("1 byte hex = 2 chars, got %d", len(tok))
	}
}

func TestSecureBytes(t *testing.T) {
	b, err := SecureBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(b))
	}
	// Check not all zeros (extremely unlikely)
	allZero := true
	for _, x := range b {
		if x != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("SecureBytes should not return all zeros")
	}

	_, err = SecureBytes(0)
	if err == nil {
		t.Error("size 0 should error")
	}
	_, err = SecureBytes(65537)
	if err == nil {
		t.Error("size > 65536 should error")
	}
}

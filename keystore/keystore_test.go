package keystore

import (
	"errors"
	"testing"
)

func TestNewAndSealOpen(t *testing.T) {
	store := New()
	password := []byte("test-password-123")

	_, err := store.GenerateKEMKey("kem-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GenerateSigningKey("sign-1")
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := store.Seal(password)
	if err != nil {
		t.Fatal(err)
	}

	store2, err := Open(sealed, password)
	if err != nil {
		t.Fatal(err)
	}

	keys := store2.List()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	// Verify KEM key round-trips.
	kp, err := store2.KEMKey("kem-1")
	if err != nil {
		t.Fatal(err)
	}
	if kp == nil {
		t.Fatal("expected non-nil KEM key pair")
	}

	// Verify signing key round-trips.
	skp, err := store2.SigningKey("sign-1")
	if err != nil {
		t.Fatal(err)
	}
	if skp == nil {
		t.Fatal("expected non-nil signing key pair")
	}
}

func TestWrongPassword(t *testing.T) {
	store := New()
	sealed, err := store.Seal([]byte("correct"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(sealed, []byte("wrong"))
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestEmptyPassword(t *testing.T) {
	store := New()
	_, err := store.Seal([]byte{})
	if !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
	_, err = Open([]byte("data-too-short"), []byte{})
	if !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
}

func TestDuplicateLabel(t *testing.T) {
	store := New()
	_, err := store.GenerateKEMKey("dup")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GenerateKEMKey("dup")
	if !errors.Is(err, ErrLabelExists) {
		t.Fatalf("expected ErrLabelExists, got %v", err)
	}
}

func TestEmptyLabel(t *testing.T) {
	store := New()
	_, err := store.GenerateKEMKey("")
	if !errors.Is(err, ErrEmptyLabel) {
		t.Fatalf("expected ErrEmptyLabel, got %v", err)
	}
}

func TestLabelWithAt(t *testing.T) {
	store := New()
	_, err := store.GenerateKEMKey("bad@label")
	if err == nil {
		t.Fatal("expected error for label with @")
	}
}

func TestTypeMismatch(t *testing.T) {
	store := New()
	_, err := store.GenerateKEMKey("my-kem")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.SigningKey("my-kem")
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("expected ErrTypeMismatch, got %v", err)
	}
}

func TestNotFound(t *testing.T) {
	store := New()
	_, err := store.KEMKey("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPublicKeyRetired(t *testing.T) {
	store := New()
	_, err := store.GenerateKEMKey("rotate-me")
	if err != nil {
		t.Fatal(err)
	}

	// Get public key before rotation.
	pub1, err := store.KEMPublicKey("rotate-me")
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Rotate("rotate-me")
	if err != nil {
		t.Fatal(err)
	}

	// Retired key still accessible via versioned label.
	retiredPub, err := store.KEMPublicKey("rotate-me@v1")
	if err != nil {
		t.Fatal(err)
	}

	pub1Bytes, _ := pub1.MarshalBinary()
	retiredBytes, _ := retiredPub.MarshalBinary()
	if string(pub1Bytes) != string(retiredBytes) {
		t.Fatal("retired key public key mismatch")
	}

	// Active key at original label is different.
	pub2, err := store.KEMPublicKey("rotate-me")
	if err != nil {
		t.Fatal(err)
	}
	pub2Bytes, _ := pub2.MarshalBinary()
	if string(pub1Bytes) == string(pub2Bytes) {
		t.Fatal("new key should differ from old key")
	}
}

func TestRotation(t *testing.T) {
	store := New()
	id1, err := store.GenerateKEMKey("rot")
	if err != nil {
		t.Fatal(err)
	}

	id2, err := store.Rotate("rot")
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatal("new ID should differ from old ID")
	}

	// Check version.
	keys := store.List()
	for _, k := range keys {
		if k.Label == "rot" && k.Version != 2 {
			t.Fatalf("expected version 2, got %d", k.Version)
		}
		if k.Label == "rot@v1" && k.Status != Retired {
			t.Fatal("old key should be retired")
		}
	}

	// Retired key: full key pair access denied.
	_, err = store.KEMKey("rot@v1")
	if !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("expected ErrKeyRetired, got %v", err)
	}
}

func TestRotateSigning(t *testing.T) {
	store := New()
	_, err := store.GenerateSigningKey("sig")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Rotate("sig")
	if err != nil {
		t.Fatal(err)
	}

	// New signing key should work.
	skp, err := store.SigningKey("sig")
	if err != nil {
		t.Fatal(err)
	}
	if skp == nil {
		t.Fatal("expected non-nil signing key pair")
	}
}

func TestDelete(t *testing.T) {
	store := New()
	_, err := store.GenerateKEMKey("del")
	if err != nil {
		t.Fatal(err)
	}
	err = store.Delete("del")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.KEMKey("del")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	store := New()
	err := store.Delete("nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	store := New()
	_, _ = store.GenerateKEMKey("b-key")
	_, _ = store.GenerateSigningKey("a-key")

	keys := store.List()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	// Should be sorted by label.
	if keys[0].Label != "a-key" {
		t.Fatalf("expected first key label 'a-key', got %q", keys[0].Label)
	}
	if keys[1].Label != "b-key" {
		t.Fatalf("expected second key label 'b-key', got %q", keys[1].Label)
	}
}

func TestSealOpenPreservesKeys(t *testing.T) {
	store := New()
	_, _ = store.GenerateKEMKey("kem")
	_, _ = store.GenerateSigningKey("sign")

	// Get original keys.
	origKEM, _ := store.KEMKey("kem")
	origSign, _ := store.SigningKey("sign")

	password := []byte("roundtrip")
	sealed, err := store.Seal(password)
	if err != nil {
		t.Fatal(err)
	}

	store2, err := Open(sealed, password)
	if err != nil {
		t.Fatal(err)
	}

	// Verify KEM key pair.
	restoredKEM, err := store2.KEMKey("kem")
	if err != nil {
		t.Fatal(err)
	}
	origKEMBytes, _ := origKEM.MarshalKeyPair()
	restoredKEMBytes, _ := restoredKEM.MarshalKeyPair()
	if string(origKEMBytes) != string(restoredKEMBytes) {
		t.Fatal("KEM key pair mismatch after round-trip")
	}

	// Verify signing key pair.
	restoredSign, err := store2.SigningKey("sign")
	if err != nil {
		t.Fatal(err)
	}
	origSignBytes, _ := origSign.MarshalKeyPair()
	restoredSignBytes, _ := restoredSign.MarshalKeyPair()
	if string(origSignBytes) != string(restoredSignBytes) {
		t.Fatal("signing key pair mismatch after round-trip")
	}
}

func TestInvalidData(t *testing.T) {
	_, err := Open([]byte("short"), []byte("pass"))
	if !errors.Is(err, ErrInvalidData) {
		t.Fatalf("expected ErrInvalidData, got %v", err)
	}
}

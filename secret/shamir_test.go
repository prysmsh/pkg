package secret

import (
	"bytes"
	"testing"
)

func TestSplitCombine(t *testing.T) {
	secret := []byte("my-recovery-key-32-bytes-long!!")
	parts, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 5 {
		t.Errorf("expected 5 parts, got %d", len(parts))
	}
	recombined, err := Combine(parts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recombined) {
		t.Error("recombined secret does not match original")
	}
}

func TestSplitCombineSubset(t *testing.T) {
	secret := []byte("secret-data")
	parts, _ := Split(secret, 5, 3)
	// 3 parts should be enough
	subset := [][]byte{parts[0], parts[2], parts[4]}
	recombined, err := Combine(subset)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recombined) {
		t.Error("subset reconstruction failed")
	}
}

func TestSplitCombineInvalid(t *testing.T) {
	secret := []byte("x")
	_, err := Split(secret, 5, 6)
	if err == nil {
		t.Error("threshold > parts should error")
	}
	_, err = Split(secret, 5, 1)
	if err == nil {
		t.Error("threshold 1 should error")
	}
	_, err = Split(nil, 5, 3)
	if err == nil {
		t.Error("nil secret should error")
	}
	_, err = Split(secret, 1, 1)
	if err == nil {
		t.Error("parts < 2 should error")
	}
	_, err = Split(secret, 256, 2)
	if err == nil {
		t.Error("parts > 255 should error")
	}

	_, err = Combine(nil)
	if err == nil {
		t.Error("nil parts should error")
	}
	_, err = Combine([][]byte{})
	if err == nil {
		t.Error("empty parts should error")
	}

	parts, _ := Split(secret, 5, 3)
	_, err = Combine(parts[:1])
	if err == nil {
		t.Error("insufficient parts should error")
	}
}

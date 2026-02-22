package encfile

import (
	"bytes"
	"testing"

	"github.com/prysmsh/pkg/kdf"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("hello, secret world")

	ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) < HeaderSize+len(plaintext) {
		t.Error("ciphertext too short")
	}
	if ct[0] != Version {
		t.Error("version byte wrong")
	}

	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, pt) {
		t.Error("decrypted plaintext mismatch")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key := make([]byte, KeySize)
	ct, _ := Encrypt(key, []byte("secret"))

	wrongKey := make([]byte, KeySize)
	wrongKey[0] = 0xff

	_, err := Decrypt(wrongKey, ct)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestDecryptTampered(t *testing.T) {
	key := make([]byte, KeySize)
	ct, _ := Encrypt(key, []byte("secret"))
	ct[len(ct)-1] ^= 0xff

	_, err := Decrypt(key, ct)
	if err == nil {
		t.Error("decrypt tampered ciphertext should fail")
	}
}

func TestDecryptWrongVersion(t *testing.T) {
	key := make([]byte, KeySize)
	ct, _ := Encrypt(key, []byte("secret"))
	ct[0] = 99

	_, err := Decrypt(key, ct)
	if err == nil {
		t.Error("decrypt wrong version should fail")
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	_, err := Encrypt(make([]byte, 16), []byte("data"))
	if err == nil {
		t.Error("short key should error")
	}
	_, err = Encrypt(make([]byte, 64), []byte("data"))
	if err == nil {
		t.Error("long key should error")
	}
}

func TestDecryptInvalidKeySize(t *testing.T) {
	_, err := Decrypt(make([]byte, 16), make([]byte, HeaderSize+16))
	if err == nil {
		t.Error("short key should error")
	}
}

func TestDecryptCiphertextTooShort(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := Decrypt(key, make([]byte, HeaderSize-1))
	if err == nil {
		t.Error("ciphertext shorter than HeaderSize should error")
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	key := make([]byte, KeySize)
	ct, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(pt))
	}
}

func TestEncryptNonceUniqueness(t *testing.T) {
	key := make([]byte, KeySize)
	ct1, _ := Encrypt(key, []byte("same"))
	ct2, _ := Encrypt(key, []byte("same"))
	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of same plaintext should produce different ciphertext")
	}
}

func TestEncryptWithKDF(t *testing.T) {
	master := []byte("master-secret-key")
	salt := []byte("salt")
	info := []byte("encfile-v1")
	key, err := kdf.HKDF(master, salt, info, KeySize)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("agent-token")

	ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, pt) {
		t.Error("round-trip failed")
	}
}

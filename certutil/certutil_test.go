package certutil

import (
	"bytes"
	"errors"
	"testing"

	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/pqc/sign"
)

func TestSelfSignedWithPQC(t *testing.T) {
	kemKP, err := pqc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signKP, err := sign.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := SelfSigned(Options{
		CommonName:     "test.example.com",
		DNSNames:       []string{"test.example.com"},
		IsCA:           true,
		KEMPublicKey:   kemKP.PublicKey(),
		SigningKeyPair: signKP,
	})
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Certificate == nil {
		t.Fatal("certificate should not be nil")
	}
	if bundle.DER == nil {
		t.Fatal("DER should not be nil")
	}
	if bundle.PrivateKey == nil {
		t.Fatal("private key should not be nil")
	}
	if bundle.Certificate.Subject.CommonName != "test.example.com" {
		t.Fatalf("unexpected CN: %s", bundle.Certificate.Subject.CommonName)
	}
}

func TestExtractKEMKey(t *testing.T) {
	kemKP, _ := pqc.GenerateKeyPair()
	signKP, _ := sign.GenerateSigningKeyPair()

	bundle, err := SelfSigned(Options{
		CommonName:     "kem-test",
		KEMPublicKey:   kemKP.PublicKey(),
		SigningKeyPair: signKP,
	})
	if err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractKEMKey(bundle.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	origBytes, _ := kemKP.PublicKey().MarshalBinary()
	extractedBytes, _ := extracted.MarshalBinary()
	if !bytes.Equal(origBytes, extractedBytes) {
		t.Fatal("extracted KEM key doesn't match original")
	}
}

func TestExtractSigningKey(t *testing.T) {
	kemKP, _ := pqc.GenerateKeyPair()
	signKP, _ := sign.GenerateSigningKeyPair()

	bundle, err := SelfSigned(Options{
		CommonName:     "sign-test",
		KEMPublicKey:   kemKP.PublicKey(),
		SigningKeyPair: signKP,
	})
	if err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractSigningKey(bundle.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	origBytes, _ := signKP.PublicKey().MarshalBinary()
	extractedBytes, _ := extracted.MarshalBinary()
	if !bytes.Equal(origBytes, extractedBytes) {
		t.Fatal("extracted signing key doesn't match original")
	}
}

func TestVerifyPQCSelfSigned(t *testing.T) {
	kemKP, _ := pqc.GenerateKeyPair()
	signKP, _ := sign.GenerateSigningKeyPair()

	bundle, err := SelfSigned(Options{
		CommonName:     "verify-test",
		KEMPublicKey:   kemKP.PublicKey(),
		SigningKeyPair: signKP,
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyPQC(bundle.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("PQC verification should pass for self-signed cert")
	}
}

func TestVerifyPQCWrongKey(t *testing.T) {
	kemKP, _ := pqc.GenerateKeyPair()
	signKP, _ := sign.GenerateSigningKeyPair()
	wrongKP, _ := sign.GenerateSigningKeyPair()

	bundle, err := SelfSigned(Options{
		CommonName:     "wrong-key-test",
		KEMPublicKey:   kemKP.PublicKey(),
		SigningKeyPair: signKP,
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyPQC(bundle.Certificate, wrongKP.PublicKey())
	if ok {
		t.Fatal("PQC verification should fail with wrong key")
	}
	if !errors.Is(err, ErrPQCVerifyFailed) {
		t.Fatalf("expected ErrPQCVerifyFailed, got %v", err)
	}
}

func TestIssueLeafCert(t *testing.T) {
	// Create CA.
	caKEM, _ := pqc.GenerateKeyPair()
	caSign, _ := sign.GenerateSigningKeyPair()

	ca, err := SelfSigned(Options{
		CommonName:     "Test CA",
		IsCA:           true,
		KEMPublicKey:   caKEM.PublicKey(),
		SigningKeyPair: caSign,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Issue leaf.
	leafKEM, _ := pqc.GenerateKeyPair()
	leafSign, _ := sign.GenerateSigningKeyPair()

	leaf, err := Issue(Options{
		CommonName:     "leaf.example.com",
		DNSNames:       []string{"leaf.example.com"},
		KEMPublicKey:   leafKEM.PublicKey(),
		SigningKeyPair: leafSign,
		Parent:         ca.Certificate,
		ParentKey:      ca.PrivateKey,
		ParentSigner:   caSign,
	})
	if err != nil {
		t.Fatal(err)
	}

	if leaf.Certificate.Subject.CommonName != "leaf.example.com" {
		t.Fatalf("unexpected leaf CN: %s", leaf.Certificate.Subject.CommonName)
	}

	// Verify PQC signature using CA's signing key.
	ok, err := VerifyPQC(leaf.Certificate, caSign.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("PQC verification should pass for issued cert")
	}

	// Extract keys from leaf.
	_, err = ExtractKEMKey(leaf.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ExtractSigningKey(leaf.Certificate)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPEMRoundTrip(t *testing.T) {
	signKP, _ := sign.GenerateSigningKeyPair()

	bundle, err := SelfSigned(Options{
		CommonName:     "pem-test",
		SigningKeyPair: signKP,
	})
	if err != nil {
		t.Fatal(err)
	}

	pemData := EncodeCertPEM(bundle.DER)
	if len(pemData) == 0 {
		t.Fatal("PEM encoding produced empty result")
	}

	decoded, err := DecodeCertPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Subject.CommonName != "pem-test" {
		t.Fatalf("unexpected CN after PEM round-trip: %s", decoded.Subject.CommonName)
	}
}

func TestDecodePEMInvalid(t *testing.T) {
	_, err := DecodeCertPEM([]byte("not-pem"))
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestNoPQCExtensions(t *testing.T) {
	// Cert without PQC extensions.
	bundle, err := SelfSigned(Options{CommonName: "no-pqc"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ExtractKEMKey(bundle.Certificate)
	if !errors.Is(err, ErrNoKEMKey) {
		t.Fatalf("expected ErrNoKEMKey, got %v", err)
	}

	_, err = ExtractSigningKey(bundle.Certificate)
	if !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}

	_, err = ExtractPQCSignature(bundle.Certificate)
	if !errors.Is(err, ErrNoPQCSignature) {
		t.Fatalf("expected ErrNoPQCSignature, got %v", err)
	}
}

func TestMutualTLSConfig(t *testing.T) {
	signKP, _ := sign.GenerateSigningKeyPair()
	kemKP, _ := pqc.GenerateKeyPair()

	ca, err := SelfSigned(Options{
		CommonName:     "Test CA",
		IsCA:           true,
		KEMPublicKey:   kemKP.PublicKey(),
		SigningKeyPair: signKP,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := MutualTLSConfig(ca.Certificate, ca.DER, ca.PrivateKey, ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("TLS config should not be nil")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatal("expected 1 certificate in TLS config")
	}
}

func TestSelfSignedWithoutSigningKey(t *testing.T) {
	kemKP, _ := pqc.GenerateKeyPair()

	bundle, err := SelfSigned(Options{
		CommonName:   "no-sign",
		KEMPublicKey: kemKP.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// KEM key should be extractable.
	_, err = ExtractKEMKey(bundle.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	// No PQC signature (since no signing key was provided).
	_, err = ExtractPQCSignature(bundle.Certificate)
	if !errors.Is(err, ErrNoPQCSignature) {
		t.Fatalf("expected ErrNoPQCSignature, got %v", err)
	}
}

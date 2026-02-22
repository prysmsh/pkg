package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func TestPinCertificates_Disabled(t *testing.T) {
	os.Unsetenv("TLS_PIN_ENABLED")
	cfg := &tls.Config{}
	PinCertificates(cfg, []*x509.Certificate{{}})
	if cfg.VerifyConnection != nil {
		t.Error("PinCertificates should be no-op when TLS_PIN_ENABLED not set")
	}
}

func TestPinCertificates_Enabled(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")

	cert, _ := generateTestCert()
	cfg := &tls.Config{ServerName: "test"}
	PinCertificates(cfg, []*x509.Certificate{cert})
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection should be set")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must not be set; standard TLS validation should remain active")
	}
}

func TestPinCertificates_CallbackMatch(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")

	cert, _ := generateTestCert()
	cfg := &tls.Config{}
	PinCertificates(cfg, []*x509.Certificate{cert})

	// Matching peer certificate should pass.
	err := cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	})
	if err != nil {
		t.Errorf("expected match, got: %v", err)
	}

	// Non-matching peer certificate should fail.
	other, _ := generateTestCert()
	err = cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{other},
	})
	if err == nil {
		t.Error("expected mismatch error")
	}
}

func TestPinPublicKeys_Disabled(t *testing.T) {
	os.Unsetenv("TLS_PIN_ENABLED")
	cfg := &tls.Config{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	PinPublicKeys(cfg, []interface{}{key.Public()})
	if cfg.VerifyConnection != nil {
		t.Error("PinPublicKeys should be no-op when TLS_PIN_ENABLED not set")
	}
}

func TestPinPublicKeys_Enabled(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")

	cert, key := generateTestCert()
	cfg := &tls.Config{}
	PinPublicKeys(cfg, []interface{}{key.Public()})
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection should be set")
	}

	// Matching key should pass.
	err := cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	})
	if err != nil {
		t.Errorf("expected match, got: %v", err)
	}

	// Non-matching key should fail.
	other, _ := generateTestCert()
	err = cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{other},
	})
	if err == nil {
		t.Error("expected mismatch error")
	}
}

func TestPinCertificates_NilConfig(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")
	// Should not panic.
	PinCertificates(nil, []*x509.Certificate{{}})
}

func TestPinCertificates_EmptyCerts(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")
	cfg := &tls.Config{}
	PinCertificates(cfg, []*x509.Certificate{})
	if cfg.VerifyConnection != nil {
		t.Error("empty certs should be no-op")
	}
}

func TestPinPublicKeys_NilConfig(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")
	PinPublicKeys(nil, []interface{}{"not-a-key"})
}

func TestPinPublicKeys_EmptyKeys(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")
	cfg := &tls.Config{}
	PinPublicKeys(cfg, []interface{}{})
	if cfg.VerifyConnection != nil {
		t.Error("empty keys should be no-op")
	}
}

func TestPinPublicKeys_InvalidKeys(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")
	cfg := &tls.Config{}
	// "not-a-key" can't be marshaled, so pinnedDER ends up empty.
	PinPublicKeys(cfg, []interface{}{"not-a-key"})
	if cfg.VerifyConnection != nil {
		t.Error("all-invalid keys should be no-op")
	}
}

func TestPinCertificates_VerifiedChains(t *testing.T) {
	os.Setenv("TLS_PIN_ENABLED", "true")
	defer os.Unsetenv("TLS_PIN_ENABLED")

	cert, _ := generateTestCert()
	cfg := &tls.Config{}
	PinCertificates(cfg, []*x509.Certificate{cert})

	// Match via VerifiedChains (not PeerCertificates).
	err := cfg.VerifyConnection(tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert}},
	})
	if err != nil {
		t.Errorf("expected match via verified chains, got: %v", err)
	}
}

func generateTestCert() (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

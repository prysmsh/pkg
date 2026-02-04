package tlsutil

import (
	"crypto/tls"
	"os"
	"testing"
)

func TestApplyPQCConfig_Default(t *testing.T) {
	os.Unsetenv("TLS_PQC_ENABLED")
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	ApplyPQCConfig(cfg)
	if cfg.CurvePreferences != nil {
		t.Errorf("expected nil CurvePreferences (use Go default with PQC), got %v", cfg.CurvePreferences)
	}
}

func TestApplyPQCConfig_Disabled(t *testing.T) {
	os.Setenv("TLS_PQC_ENABLED", "false")
	defer os.Unsetenv("TLS_PQC_ENABLED")
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	ApplyPQCConfig(cfg)
	if len(cfg.CurvePreferences) == 0 {
		t.Error("expected CurvePreferences set when PQC disabled")
	}
	// Should not include X25519MLKEM768 (CurveID 45881, TLS 1.3 only)
	const x25519MLKEM768 = 45881
	for _, c := range cfg.CurvePreferences {
		if c == tls.CurveID(x25519MLKEM768) {
			t.Error("CurvePreferences should not include X25519MLKEM768 when PQC disabled")
		}
	}
}

func TestApplyPQCConfig_ExplicitEnabled(t *testing.T) {
	os.Setenv("TLS_PQC_ENABLED", "true")
	defer os.Unsetenv("TLS_PQC_ENABLED")
	cfg := &tls.Config{}
	ApplyPQCConfig(cfg)
	if cfg.CurvePreferences != nil {
		t.Errorf("expected nil when PQC enabled, got %v", cfg.CurvePreferences)
	}
}

func TestApplyPQCConfig_NilConfig(t *testing.T) {
	// Should not panic
	ApplyPQCConfig(nil)
}

func TestDefaultClientConfig(t *testing.T) {
	os.Unsetenv("TLS_PQC_ENABLED")
	cfg := DefaultClientConfig()
	if cfg == nil {
		t.Fatal("DefaultClientConfig returned nil")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want TLS12", cfg.MinVersion)
	}
	if cfg.CurvePreferences != nil {
		t.Errorf("expected nil CurvePreferences when PQC enabled, got %v", cfg.CurvePreferences)
	}
}

func TestDefaultServerConfig(t *testing.T) {
	os.Unsetenv("TLS_PQC_ENABLED")
	cfg := DefaultServerConfig()
	if cfg == nil {
		t.Fatal("DefaultServerConfig returned nil")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want TLS12", cfg.MinVersion)
	}
}

func ExampleDefaultClientConfig() {
	cfg := DefaultClientConfig()
	_ = cfg // use with tls.Dial, http.Transport, etc.
}

func ExampleApplyPQCConfig() {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	ApplyPQCConfig(cfg)
	// cfg now has PQC settings based on TLS_PQC_ENABLED env
}

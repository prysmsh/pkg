// Package tlsutil provides TLS configuration helpers for post-quantum cryptography.
package tlsutil

import (
	"crypto/tls"
	"os"
	"strings"
)

// CurvePreferences without PQC (X25519MLKEM768 excluded).
// Used when TLS_PQC_ENABLED=false for compatibility with older peers.
var curvesNoPQC = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// ApplyPQCConfig applies TLS PQC settings based on the TLS_PQC_ENABLED env var.
// When true (default), Go 1.24+ uses X25519MLKEM768 hybrid key exchange by default.
// When false, CurvePreferences is set to exclude PQC for compatibility.
//
// Call this on tls.Config before use (client or server).
func ApplyPQCConfig(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	if strings.ToLower(strings.TrimSpace(os.Getenv("TLS_PQC_ENABLED"))) == "false" {
		cfg.CurvePreferences = curvesNoPQC
	}
}

// DefaultClientConfig returns a TLS config suitable for client connections.
// MinVersion is TLS 1.2; PQC settings are applied via ApplyPQCConfig.
func DefaultClientConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	ApplyPQCConfig(cfg)
	return cfg
}

// DefaultServerConfig returns a TLS config suitable for server connections.
// MinVersion is TLS 1.2; PQC settings are applied via ApplyPQCConfig.
func DefaultServerConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	ApplyPQCConfig(cfg)
	return cfg
}

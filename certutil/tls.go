package certutil

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"github.com/prysmsh/pkg/tlsutil"
)

// MutualTLSConfig creates a TLS configuration for mutual TLS authentication
// using the given certificate and CA. PQC settings are applied via tlsutil.
// The key parameter accepts any crypto.PrivateKey (ed25519, RSA, ECDSA, etc.).
func MutualTLSConfig(cert *x509.Certificate, certDER []byte, key crypto.PrivateKey, caCert *x509.Certificate) (*tls.Config, error) {
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caPool,
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	tlsutil.ApplyPQCConfig(cfg)

	return cfg, nil
}

// EncodeCertPEM encodes a DER-encoded certificate as PEM.
func EncodeCertPEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

// DecodeCertPEM decodes a PEM-encoded certificate.
func DecodeCertPEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidCertificate
	}
	return x509.ParseCertificate(block.Bytes)
}

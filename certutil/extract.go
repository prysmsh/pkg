package certutil

import (
	"crypto/x509"

	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/pqc/sign"
)

// ExtractKEMKey extracts the PQC KEM public key from a certificate's extensions.
func ExtractKEMKey(cert *x509.Certificate) (*pqc.HybridPublicKey, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDPQCKEMPublicKey) {
			return pqc.UnmarshalPublicKey(ext.Value)
		}
	}
	return nil, ErrNoKEMKey
}

// ExtractSigningKey extracts the PQC signing public key from a certificate's extensions.
func ExtractSigningKey(cert *x509.Certificate) (*sign.HybridPublicKey, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDPQCSigningPubKey) {
			return sign.UnmarshalPublicKey(ext.Value)
		}
	}
	return nil, ErrNoSigningKey
}

// ExtractPQCSignature extracts the raw PQC signature bytes from a certificate's extensions.
func ExtractPQCSignature(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDPQCSignature) {
			return ext.Value, nil
		}
	}
	return nil, ErrNoPQCSignature
}

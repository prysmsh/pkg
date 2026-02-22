package certutil

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/pqc/sign"
)

// BuildKEMExtension creates an X.509 extension for a PQC KEM public key.
// This is intended for external code (e.g. an RSA CA) that builds its own
// certificate templates rather than using SelfSigned/Issue.
func BuildKEMExtension(pub *pqc.HybridPublicKey) (pkix.Extension, error) {
	kemBytes, err := pub.MarshalBinary()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDPQCKEMPublicKey,
		Critical: false,
		Value:    kemBytes,
	}, nil
}

// BuildSigningExtension creates an X.509 extension for a PQC signing public key.
func BuildSigningExtension(pub *sign.HybridPublicKey) (pkix.Extension, error) {
	sigPubBytes, err := pub.MarshalBinary()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDPQCSigningPubKey,
		Critical: false,
		Value:    sigPubBytes,
	}, nil
}

// SignCertPQC adds a PQC signature extension to a DER-encoded certificate
// and re-creates it. The signer is typically the CA's PQC signing key pair.
// This is the exported form of addPQCSignature for use by external CAs.
func SignCertPQC(der []byte, template *x509.Certificate, leafPub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, signer *sign.HybridSigningKeyPair) ([]byte, error) {
	return addPQCSignature(der, template, leafPub, parent, parentKey, signer)
}

package certutil

import (
	"crypto/x509"

	"github.com/prysmsh/pkg/pqc/sign"
)

// VerifyPQC verifies the PQC signature on a certificate.
// If issuerSigningPub is nil, the certificate is treated as self-signed
// and its own embedded signing public key is used for verification.
func VerifyPQC(cert *x509.Certificate, issuerSigningPub *sign.HybridPublicKey) (bool, error) {
	sig, err := ExtractPQCSignature(cert)
	if err != nil {
		return false, err
	}

	verifyKey := issuerSigningPub
	if verifyKey == nil {
		// Self-signed: use the cert's own signing key.
		verifyKey, err = ExtractSigningKey(cert)
		if err != nil {
			return false, err
		}
	}

	signedContent := buildSignedContent(cert)
	if !sign.Verify(verifyKey, signedContent, sig) {
		return false, ErrPQCVerifyFailed
	}

	return true, nil
}

// Package certutil provides PQC certificate helpers for X.509 certificates
// with embedded post-quantum keys and signatures.
//
// Certificates use Ed25519 as the X.509 signature algorithm for compatibility
// with existing TLS infrastructure. PQC keys and signatures are embedded as
// non-critical X.509 v3 extensions with custom OIDs. PQC-aware peers verify
// both; non-PQC peers ignore the extensions.
package certutil

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net"
	"time"

	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/pqc/sign"
)

// OIDs under the placeholder arc 1.3.6.1.4.1.59999.1.
var (
	OIDPQCKEMPublicKey  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}
	OIDPQCSigningPubKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 2}
	OIDPQCSignature     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 3}
)

// Sentinel errors for programmatic error handling.
var (
	ErrNoPQCExtension     = errors.New("certutil: no PQC extension found")
	ErrNoKEMKey           = errors.New("certutil: no KEM public key extension")
	ErrNoSigningKey       = errors.New("certutil: no signing public key extension")
	ErrNoPQCSignature     = errors.New("certutil: no PQC signature extension")
	ErrPQCVerifyFailed    = errors.New("certutil: PQC signature verification failed")
	ErrInvalidCertificate = errors.New("certutil: invalid certificate")
	ErrMissingSigningKey  = errors.New("certutil: signing key pair required for PQC signature")
)

// Options configures certificate generation.
type Options struct {
	CommonName   string
	Organization []string
	DNSNames     []string
	IPAddresses  []net.IP
	NotBefore    time.Time
	NotAfter     time.Time
	IsCA         bool

	// PQC extensions to embed.
	KEMPublicKey   *pqc.HybridPublicKey
	SigningKeyPair *sign.HybridSigningKeyPair

	// For Issue: parent certificate and signing material.
	Parent       *x509.Certificate
	ParentKey    crypto.Signer
	ParentSigner *sign.HybridSigningKeyPair
}

// CertificateBundle holds a generated certificate and its keys.
type CertificateBundle struct {
	Certificate *x509.Certificate // parsed certificate
	DER         []byte            // raw DER-encoded certificate
	PrivateKey  crypto.Signer
}

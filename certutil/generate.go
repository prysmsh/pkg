package certutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/pqc/sign"
)

// SelfSigned generates a self-signed X.509 certificate with optional PQC extensions.
// An Ed25519 key pair is generated internally for X.509 compatibility.
func SelfSigned(opts Options) (*CertificateBundle, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, err
	}

	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now()
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = notBefore.Add(365 * 24 * time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
		},
		DNSNames:    opts.DNSNames,
		IPAddresses: opts.IPAddresses,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if opts.IsCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Add PQC extensions (non-critical).
	exts, err := buildPQCExtensions(opts.KEMPublicKey, opts.SigningKeyPair)
	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = exts

	// First pass: create certificate without PQC signature.
	der, err := x509.CreateCertificate(rand.Reader, template, template, edPub, edPriv)
	if err != nil {
		return nil, err
	}

	// If we have a signing key pair, add PQC signature (second pass).
	if opts.SigningKeyPair != nil {
		der, err = addPQCSignature(der, template, edPub, template, edPriv, opts.SigningKeyPair)
		if err != nil {
			return nil, err
		}
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &CertificateBundle{
		Certificate: cert,
		DER:         der,
		PrivateKey:  edPriv,
	}, nil
}

// Issue generates a leaf certificate signed by a CA.
// The leaf key pair is always Ed25519; ParentKey may be any crypto.Signer (e.g. RSA, Ed25519).
func Issue(opts Options) (*CertificateBundle, error) {
	if opts.Parent == nil || opts.ParentKey == nil {
		return nil, ErrInvalidCertificate
	}

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, err
	}

	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now()
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = notBefore.Add(365 * 24 * time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
		},
		DNSNames:    opts.DNSNames,
		IPAddresses: opts.IPAddresses,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Add PQC extensions.
	exts, err := buildPQCExtensions(opts.KEMPublicKey, opts.SigningKeyPair)
	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = exts

	// First pass: create certificate signed by parent.
	der, err := x509.CreateCertificate(rand.Reader, template, opts.Parent, edPub, opts.ParentKey)
	if err != nil {
		return nil, err
	}

	// Add PQC signature from parent signer if available.
	signer := opts.ParentSigner
	if signer == nil {
		signer = opts.SigningKeyPair
	}
	if signer != nil {
		der, err = addPQCSignature(der, template, edPub, opts.Parent, opts.ParentKey, signer)
		if err != nil {
			return nil, err
		}
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &CertificateBundle{
		Certificate: cert,
		DER:         der,
		PrivateKey:  edPriv,
	}, nil
}

// addPQCSignature re-creates the certificate with a PQC signature extension.
func addPQCSignature(der []byte, template *x509.Certificate, leafPub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, signer *sign.HybridSigningKeyPair) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	// Compute signed content: RawSubjectPublicKeyInfo || RawSubject || kemExtBytes || signExtBytes.
	signedContent := buildSignedContent(cert)

	sig, err := signer.Sign(signedContent)
	if err != nil {
		return nil, err
	}

	// Add PQC signature as extension.
	sigExt := pkix.Extension{
		Id:       OIDPQCSignature,
		Critical: false,
		Value:    sig,
	}

	// Rebuild template with all extensions including PQC signature.
	template.ExtraExtensions = append(template.ExtraExtensions, sigExt)

	return x509.CreateCertificate(rand.Reader, template, parent, leafPub, parentKey)
}

// buildPQCExtensions creates the X.509 extensions for PQC key material.
func buildPQCExtensions(kemPub *pqc.HybridPublicKey, sigKP *sign.HybridSigningKeyPair) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	if kemPub != nil {
		kemBytes, err := kemPub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{
			Id:       OIDPQCKEMPublicKey,
			Critical: false,
			Value:    kemBytes,
		})
	}

	if sigKP != nil {
		sigPubBytes, err := sigKP.PublicKey().MarshalBinary()
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{
			Id:       OIDPQCSigningPubKey,
			Critical: false,
			Value:    sigPubBytes,
		})
	}

	return exts, nil
}

// buildSignedContent constructs the canonical content for PQC signature.
func buildSignedContent(cert *x509.Certificate) []byte {
	var content []byte
	content = append(content, cert.RawSubjectPublicKeyInfo...)
	content = append(content, cert.RawSubject...)

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDPQCKEMPublicKey) || ext.Id.Equal(OIDPQCSigningPubKey) {
			content = append(content, ext.Value...)
		}
	}

	return content
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

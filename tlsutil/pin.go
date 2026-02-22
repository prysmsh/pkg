// Certificate and public key pinning for TLS.
package tlsutil

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"strings"
)

var errPinnedCertMismatch = errors.New("tlsutil: peer certificate does not match pinned certificate or public key")

// PinCertificates configures cfg to verify that the peer presents one of the pinned certificates.
// Standard TLS verification (chain, hostname, expiry) is performed first; pinning is checked after.
// When TLS_PIN_ENABLED is not "true", this is a no-op.
func PinCertificates(cfg *tls.Config, certs []*x509.Certificate) {
	if cfg == nil || !isPinEnabled() {
		return
	}
	if len(certs) == 0 {
		return
	}
	pinned := make([][]byte, len(certs))
	for i, c := range certs {
		pinned[i] = c.Raw
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		for _, chain := range cs.VerifiedChains {
			for _, cert := range chain {
				for _, p := range pinned {
					if len(cert.Raw) == len(p) && subtle.ConstantTimeCompare(cert.Raw, p) == 1 {
						return nil
					}
				}
			}
		}
		// Also check peer certificates directly for client certificate pinning.
		for _, cert := range cs.PeerCertificates {
			for _, p := range pinned {
				if len(cert.Raw) == len(p) && subtle.ConstantTimeCompare(cert.Raw, p) == 1 {
					return nil
				}
			}
		}
		return errPinnedCertMismatch
	}
}

// PinPublicKeys configures cfg to verify that the peer's certificate public key matches one of the pinned keys.
// Standard TLS verification (chain, hostname, expiry) is performed first; pinning is checked after.
// When TLS_PIN_ENABLED is not "true", this is a no-op.
func PinPublicKeys(cfg *tls.Config, keys []interface{}) {
	if cfg == nil || !isPinEnabled() {
		return
	}
	if len(keys) == 0 {
		return
	}
	pinnedDER := make([][]byte, 0, len(keys))
	for _, k := range keys {
		der, err := marshalPublicKey(k)
		if err != nil {
			continue
		}
		pinnedDER = append(pinnedDER, der)
	}
	if len(pinnedDER) == 0 {
		return
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		for _, cert := range cs.PeerCertificates {
			peerDER, err := marshalPublicKey(cert.PublicKey)
			if err != nil {
				continue
			}
			for _, p := range pinnedDER {
				if len(peerDER) == len(p) && subtle.ConstantTimeCompare(peerDER, p) == 1 {
					return nil
				}
			}
		}
		return errPinnedCertMismatch
	}
}

func isPinEnabled() bool {
	return strings.ToLower(strings.TrimSpace(os.Getenv("TLS_PIN_ENABLED"))) == "true"
}

func marshalPublicKey(k interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k)
}

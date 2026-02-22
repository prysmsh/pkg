// Package channel implements a Noise-like PQC secure channel using hybrid KEM
// for key exchange, hybrid signatures for mutual authentication, and
// ChaCha20-Poly1305 for transport encryption.
//
// The XX-KEM handshake pattern provides mutual authentication with identity
// hiding: neither party's long-term identity is revealed until the session is
// encrypted.
package channel

import (
	"errors"

	"github.com/prysmsh/pkg/pqc/sign"
)

// MaxPayloadSize is the maximum plaintext size for a single Encrypt call.
const MaxPayloadSize = 1 << 24 // 16 MiB

// Sentinel errors for programmatic error handling.
var (
	ErrHandshakeNotDone    = errors.New("channel: handshake not complete")
	ErrHandshakeAlready    = errors.New("channel: handshake already complete")
	ErrUnexpectedMessage   = errors.New("channel: unexpected message for current state")
	ErrInvalidMessage      = errors.New("channel: invalid message format")
	ErrAuthenticationFailed = errors.New("channel: peer authentication failed")
	ErrDecryptionFailed    = errors.New("channel: decryption failed")
	ErrCounterExhausted    = errors.New("channel: message counter exhausted")
	ErrMaxPayloadSize      = errors.New("channel: payload exceeds maximum size")
)

// Handshake performs the XX-KEM handshake between two parties.
//
// Protocol:
//
//	Initiator                            Responder
//	msg1: ephemeral KEM pubkey    -->
//	                              <--    msg2: resp ephemeral + KEM ct + encrypted(identity)
//	msg3: KEM ct + encrypted(identity) -->
//
// After handshake completes, call Session() to obtain the encrypted transport
// and PeerIdentity() to get the authenticated peer signing public key.
type Handshake struct {
	isInitiator     bool
	step            int
	localEphemeral  kemKeyPair
	remoteEphemeral kemPublicKey
	localSigning    signingKeyPair
	peerStaticPub   *sign.HybridPublicKey // expected peer identity (nil = TOFU)
	peerIdentity    *sign.HybridPublicKey // learned during handshake
	transcript      transcriptHash
	ck1             []byte // chaining key after first KEM exchange
	session         *Session
}

// Session returns the post-handshake encrypted transport.
// Returns nil if the handshake is not yet complete.
func (h *Handshake) Session() *Session {
	return h.session
}

// PeerIdentity returns the authenticated signing public key of the remote peer.
// Returns nil if the handshake is not yet complete.
func (h *Handshake) PeerIdentity() *sign.HybridPublicKey {
	return h.peerIdentity
}

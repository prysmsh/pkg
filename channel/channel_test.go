package channel

import (
	"bytes"
	"errors"
	"testing"

	"github.com/prysmsh/pkg/pqc/sign"
)

func TestHandshakeAndTransport(t *testing.T) {
	// Generate signing keys for both parties.
	initSign, err := sign.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	respSign, err := sign.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	initiator, err := NewInitiator(initSign, respSign.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewResponder(respSign)
	if err != nil {
		t.Fatal(err)
	}

	// msg1: initiator -> responder
	msg1, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatal("msg1 write:", err)
	}
	_, err = responder.ReadMessage(msg1)
	if err != nil {
		t.Fatal("msg1 read:", err)
	}

	// msg2: responder -> initiator
	msg2, err := responder.WriteMessage(nil)
	if err != nil {
		t.Fatal("msg2 write:", err)
	}
	_, err = initiator.ReadMessage(msg2)
	if err != nil {
		t.Fatal("msg2 read:", err)
	}

	// msg3: initiator -> responder
	msg3, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatal("msg3 write:", err)
	}
	_, err = responder.ReadMessage(msg3)
	if err != nil {
		t.Fatal("msg3 read:", err)
	}

	// Verify sessions exist.
	iSession := initiator.Session()
	rSession := responder.Session()
	if iSession == nil || rSession == nil {
		t.Fatal("sessions should be non-nil after handshake")
	}

	// Verify peer identities.
	iPeer := initiator.PeerIdentity()
	rPeer := responder.PeerIdentity()
	if iPeer == nil || rPeer == nil {
		t.Fatal("peer identities should be non-nil")
	}

	// Verify peer identity matches.
	respPubBytes, _ := respSign.PublicKey().MarshalBinary()
	iPeerBytes, _ := iPeer.MarshalBinary()
	if !bytes.Equal(respPubBytes, iPeerBytes) {
		t.Fatal("initiator's peer identity should match responder's signing key")
	}

	initPubBytes, _ := initSign.PublicKey().MarshalBinary()
	rPeerBytes, _ := rPeer.MarshalBinary()
	if !bytes.Equal(initPubBytes, rPeerBytes) {
		t.Fatal("responder's peer identity should match initiator's signing key")
	}

	// Test encrypted transport.
	plaintext := []byte("hello, post-quantum world!")
	ct, err := iSession.Encrypt(plaintext)
	if err != nil {
		t.Fatal("encrypt:", err)
	}
	pt, err := rSession.Decrypt(ct)
	if err != nil {
		t.Fatal("decrypt:", err)
	}
	if !bytes.Equal(plaintext, pt) {
		t.Fatal("decrypted text doesn't match")
	}

	// Test reverse direction.
	plaintext2 := []byte("hello back!")
	ct2, err := rSession.Encrypt(plaintext2)
	if err != nil {
		t.Fatal("reverse encrypt:", err)
	}
	pt2, err := iSession.Decrypt(ct2)
	if err != nil {
		t.Fatal("reverse decrypt:", err)
	}
	if !bytes.Equal(plaintext2, pt2) {
		t.Fatal("reverse decrypted text doesn't match")
	}
}

func TestHandshakeTOFU(t *testing.T) {
	initSign, _ := sign.GenerateSigningKeyPair()
	respSign, _ := sign.GenerateSigningKeyPair()

	// nil peerStaticPub = TOFU.
	initiator, _ := NewInitiator(initSign, nil)
	responder, _ := NewResponder(respSign)

	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)
	msg2, _ := responder.WriteMessage(nil)
	initiator.ReadMessage(msg2)
	msg3, _ := initiator.WriteMessage(nil)
	_, err := responder.ReadMessage(msg3)
	if err != nil {
		t.Fatal("TOFU handshake failed:", err)
	}

	if initiator.Session() == nil {
		t.Fatal("initiator session should be non-nil")
	}
}

func TestHandshakeWrongPeerIdentity(t *testing.T) {
	initSign, _ := sign.GenerateSigningKeyPair()
	respSign, _ := sign.GenerateSigningKeyPair()
	wrongSign, _ := sign.GenerateSigningKeyPair()

	// Expect wrong peer identity.
	initiator, _ := NewInitiator(initSign, wrongSign.PublicKey())
	responder, _ := NewResponder(respSign)

	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)
	msg2, _ := responder.WriteMessage(nil)
	_, err := initiator.ReadMessage(msg2)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
	}
}

func TestHandshakeReplayMsg2(t *testing.T) {
	initSign, _ := sign.GenerateSigningKeyPair()
	respSign, _ := sign.GenerateSigningKeyPair()

	// Complete a full handshake to capture msg2.
	init1, _ := NewInitiator(initSign, nil)
	resp1, _ := NewResponder(respSign)
	msg1a, _ := init1.WriteMessage(nil)
	resp1.ReadMessage(msg1a)
	msg2a, _ := resp1.WriteMessage(nil)

	// Start a new handshake with a different initiator (different ephemeral keys).
	init2, _ := NewInitiator(initSign, nil)
	msg1b, _ := init2.WriteMessage(nil)
	_ = msg1b // sent to a real responder, but we try replaying old msg2

	// Try to use msg2 from the first session. The KEM ciphertext was
	// encapsulated to init1's ephemeral key, so init2 can't decapsulate it.
	_, err := init2.ReadMessage(msg2a)
	if err == nil {
		t.Fatal("expected error when replaying msg2 from different session")
	}
}

func TestUnexpectedMessageOrder(t *testing.T) {
	initSign, _ := sign.GenerateSigningKeyPair()
	respSign, _ := sign.GenerateSigningKeyPair()

	initiator, _ := NewInitiator(initSign, nil)
	responder, _ := NewResponder(respSign)

	// Responder tries to write before reading msg1.
	_, err := responder.WriteMessage(nil)
	if !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatalf("expected ErrUnexpectedMessage, got %v", err)
	}

	// Initiator tries to read before writing msg1.
	_, err = initiator.ReadMessage([]byte("fake"))
	if !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatalf("expected ErrUnexpectedMessage, got %v", err)
	}
}

func TestHandshakeAlready(t *testing.T) {
	initSign, _ := sign.GenerateSigningKeyPair()
	respSign, _ := sign.GenerateSigningKeyPair()

	initiator, _ := NewInitiator(initSign, nil)
	responder, _ := NewResponder(respSign)

	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)
	msg2, _ := responder.WriteMessage(nil)
	initiator.ReadMessage(msg2)
	msg3, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg3)

	// Handshake is done. Further calls should error.
	_, err := initiator.WriteMessage(nil)
	if !errors.Is(err, ErrHandshakeAlready) {
		t.Fatalf("expected ErrHandshakeAlready, got %v", err)
	}
	_, err = responder.ReadMessage([]byte("extra"))
	if !errors.Is(err, ErrHandshakeAlready) {
		t.Fatalf("expected ErrHandshakeAlready, got %v", err)
	}
}

func TestSessionMultipleMessages(t *testing.T) {
	initSign, _ := sign.GenerateSigningKeyPair()
	respSign, _ := sign.GenerateSigningKeyPair()

	initiator, _ := NewInitiator(initSign, nil)
	responder, _ := NewResponder(respSign)

	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)
	msg2, _ := responder.WriteMessage(nil)
	initiator.ReadMessage(msg2)
	msg3, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg3)

	iSession := initiator.Session()
	rSession := responder.Session()

	// Send multiple messages in each direction.
	for i := 0; i < 100; i++ {
		msg := []byte("message from initiator")
		ct, err := iSession.Encrypt(msg)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := rSession.Decrypt(ct)
		if err != nil {
			t.Fatalf("decrypt i->r message %d: %v", i, err)
		}
		if !bytes.Equal(msg, pt) {
			t.Fatal("mismatch")
		}

		msg2 := []byte("message from responder")
		ct2, err := rSession.Encrypt(msg2)
		if err != nil {
			t.Fatal(err)
		}
		pt2, err := iSession.Decrypt(ct2)
		if err != nil {
			t.Fatalf("decrypt r->i message %d: %v", i, err)
		}
		if !bytes.Equal(msg2, pt2) {
			t.Fatal("mismatch")
		}
	}
}

func TestInvalidCiphertext(t *testing.T) {
	initSign, _ := sign.GenerateSigningKeyPair()
	respSign, _ := sign.GenerateSigningKeyPair()

	initiator, _ := NewInitiator(initSign, nil)
	responder, _ := NewResponder(respSign)

	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)
	msg2, _ := responder.WriteMessage(nil)
	initiator.ReadMessage(msg2)
	msg3, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg3)

	iSession := initiator.Session()
	rSession := responder.Session()

	ct, _ := iSession.Encrypt([]byte("test"))

	// Tamper with ciphertext.
	ct[len(ct)-1] ^= 0xff
	_, err := rSession.Decrypt(ct)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestMaxPayload(t *testing.T) {
	initSign, _ := sign.GenerateSigningKeyPair()
	respSign, _ := sign.GenerateSigningKeyPair()

	initiator, _ := NewInitiator(initSign, nil)
	responder, _ := NewResponder(respSign)

	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)
	msg2, _ := responder.WriteMessage(nil)
	initiator.ReadMessage(msg2)
	msg3, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg3)

	iSession := initiator.Session()

	// Payload too large.
	big := make([]byte, MaxPayloadSize+1)
	_, err := iSession.Encrypt(big)
	if !errors.Is(err, ErrMaxPayloadSize) {
		t.Fatalf("expected ErrMaxPayloadSize, got %v", err)
	}
}

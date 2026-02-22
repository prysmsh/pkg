// Example: Post-quantum hybrid KEM and AEAD encryption.
//
// Run with: go run ./examples/pqc
package main

import (
	"fmt"
	"log"

	"github.com/prysmsh/pkg/pqc"
)

func main() {
	// 1. Recipient generates a key pair
	recipient, err := pqc.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generate key pair: %v", err)
	}
	pub := recipient.PublicKey()

	// 2. Sender encapsulates to get a shared secret and ciphertext
	ciphertext, senderSecret, err := pqc.Encapsulate(pub)
	if err != nil {
		log.Fatalf("encapsulate: %v", err)
	}

	// 3. Recipient decapsulates to recover the same shared secret
	recipientSecret, err := recipient.Decapsulate(ciphertext)
	if err != nil {
		log.Fatalf("decapsulate: %v", err)
	}

	// 4. Both sides now have the same shared secret - encrypt a message
	plaintext := []byte("Hello, post-quantum world!")
	ct, err := pqc.EncryptPayload(senderSecret, plaintext)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	pt, err := pqc.DecryptPayload(recipientSecret, ct)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}

	fmt.Printf("Encrypted and decrypted: %s\n", string(pt))
}

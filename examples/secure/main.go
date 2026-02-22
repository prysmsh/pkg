// Example: Timing-safe comparison and secure random tokens.
//
// Run with: go run ./examples/secure
package main

import (
	"fmt"
	"log"

	"github.com/prysmsh/pkg/secure"
)

func main() {
	// 1. Generate a secure session ID (e.g. for cookies, API tokens)
	sessionID, err := secure.RandomHex(32)
	if err != nil {
		log.Fatalf("random hex: %v", err)
	}
	fmt.Printf("Session ID: %s\n", sessionID)

	// 2. Generate raw random bytes (e.g. for nonces, keys)
	bytes, err := secure.RandomBytes(16)
	if err != nil {
		log.Fatalf("random bytes: %v", err)
	}
	fmt.Printf("Random bytes (hex): %x\n", bytes)

	// 3. Constant-time comparison for token validation (prevents timing attacks)
	apiToken := "sk_live_abc123"
	userInput := "sk_live_abc123"
	if !secure.ConstantTimeEqual([]byte(apiToken), []byte(userInput)) {
		log.Fatal("invalid token")
	}
	fmt.Println("Token validation passed (constant-time)")
}

// Package secret provides Shamir's Secret Sharing for splitting and reconstructing secrets.
package secret

import (
	"errors"

	"github.com/hashicorp/vault/shamir"
)

// Split divides a secret into parts shares, of which threshold are required to reconstruct.
// parts must be >= threshold, and threshold must be >= 2.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}
	if parts < 2 {
		return nil, errors.New("parts must be at least 2")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if threshold > parts {
		return nil, errors.New("threshold cannot exceed parts")
	}
	if parts > 255 {
		return nil, errors.New("parts cannot exceed 255")
	}
	return shamir.Split(secret, parts, threshold)
}

// Combine reconstructs a secret from at least the threshold number of shares.
func Combine(parts [][]byte) ([]byte, error) {
	if len(parts) == 0 {
		return nil, errors.New("parts cannot be empty")
	}
	return shamir.Combine(parts)
}

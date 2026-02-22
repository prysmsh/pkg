// Package keystore provides an encrypted PQC key store for generating, storing,
// rotating, and password-protecting hybrid KEM and signing key pairs.
package keystore

import "time"

// KeyType identifies the kind of key stored in an entry.
type KeyType string

const (
	KEMKey     KeyType = "kem"
	SigningKey KeyType = "signing"
)

// KeyStatus indicates whether a key is currently active or retired.
type KeyStatus string

const (
	Active  KeyStatus = "active"
	Retired KeyStatus = "retired"
)

// keyEntry is the internal representation of a stored key.
type keyEntry struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	Type       KeyType   `json:"type"`
	Status     KeyStatus `json:"status"`
	Created    time.Time `json:"created"`
	Rotated    time.Time `json:"rotated,omitempty"`
	Version    int       `json:"version"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
}

// KeyInfo is a public summary of a stored key, without key material.
type KeyInfo struct {
	ID      string
	Label   string
	Type    KeyType
	Status  KeyStatus
	Created time.Time
	Rotated time.Time
	Version int
}

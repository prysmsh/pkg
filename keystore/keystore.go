package keystore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prysmsh/pkg/encfile"
	"github.com/prysmsh/pkg/kdf"
	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/pqc/sign"
	"github.com/prysmsh/pkg/secure"
)

// Sentinel errors for programmatic error handling.
var (
	ErrNotFound        = errors.New("keystore: key not found")
	ErrLabelExists     = errors.New("keystore: label already exists")
	ErrInvalidPassword = errors.New("keystore: invalid password")
	ErrInvalidData     = errors.New("keystore: invalid data")
	ErrKeyRetired      = errors.New("keystore: key is retired")
	ErrTypeMismatch    = errors.New("keystore: key type mismatch")
	ErrEmptyLabel      = errors.New("keystore: label cannot be empty")
	ErrEmptyPassword   = errors.New("keystore: password cannot be empty")
)

const saltSize = 16

type storeData struct {
	Version int                  `json:"version"`
	Created time.Time            `json:"created"`
	Entries map[string]*keyEntry `json:"entries"`
}

// Store is an encrypted PQC key store.
type Store struct {
	data storeData
}

// New creates a new empty key store.
func New() *Store {
	return &Store{
		data: storeData{
			Version: 1,
			Created: time.Now().UTC(),
			Entries: make(map[string]*keyEntry),
		},
	}
}

// Open decrypts and loads a key store from sealed data.
func Open(data []byte, password []byte) (*Store, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	if len(data) < saltSize {
		return nil, ErrInvalidData
	}
	salt := data[:saltSize]
	encrypted := data[saltSize:]

	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPassword, err)
	}
	plaintext, err := encfile.Decrypt(key, encrypted)
	if err != nil {
		return nil, ErrInvalidPassword
	}

	s := &Store{}
	if err := json.Unmarshal(plaintext, &s.data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidData, err)
	}
	if s.data.Entries == nil {
		s.data.Entries = make(map[string]*keyEntry)
	}
	return s, nil
}

// Seal encrypts the store with a password and returns the sealed bytes.
// A fresh salt is generated each call.
func (s *Store) Seal(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	salt, err := secure.RandomBytes(saltSize)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(s.data)
	if err != nil {
		return nil, err
	}
	encrypted, err := encfile.Encrypt(key, plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, saltSize+len(encrypted))
	out = append(out, salt...)
	out = append(out, encrypted...)
	return out, nil
}

// GenerateKEMKey generates a new hybrid KEM key pair and stores it under the given label.
// Returns the key's unique ID.
func (s *Store) GenerateKEMKey(label string) (string, error) {
	if err := validateLabel(label); err != nil {
		return "", err
	}
	if _, exists := s.data.Entries[label]; exists {
		return "", ErrLabelExists
	}
	kp, err := pqc.GenerateKeyPair()
	if err != nil {
		return "", err
	}
	privBytes, err := kp.MarshalKeyPair()
	if err != nil {
		return "", err
	}
	pubBytes, err := kp.PublicKey().MarshalBinary()
	if err != nil {
		return "", err
	}
	id, err := secure.RandomHex(16)
	if err != nil {
		return "", err
	}
	s.data.Entries[label] = &keyEntry{
		ID:         id,
		Label:      label,
		Type:       KEMKey,
		Status:     Active,
		Created:    time.Now().UTC(),
		Version:    1,
		PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
		PrivateKey: base64.StdEncoding.EncodeToString(privBytes),
	}
	return id, nil
}

// GenerateSigningKey generates a new hybrid signing key pair and stores it under the given label.
// Returns the key's unique ID.
func (s *Store) GenerateSigningKey(label string) (string, error) {
	if err := validateLabel(label); err != nil {
		return "", err
	}
	if _, exists := s.data.Entries[label]; exists {
		return "", ErrLabelExists
	}
	kp, err := sign.GenerateSigningKeyPair()
	if err != nil {
		return "", err
	}
	privBytes, err := kp.MarshalKeyPair()
	if err != nil {
		return "", err
	}
	pubBytes, err := kp.PublicKey().MarshalBinary()
	if err != nil {
		return "", err
	}
	id, err := secure.RandomHex(16)
	if err != nil {
		return "", err
	}
	s.data.Entries[label] = &keyEntry{
		ID:         id,
		Label:      label,
		Type:       SigningKey,
		Status:     Active,
		Created:    time.Now().UTC(),
		Version:    1,
		PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
		PrivateKey: base64.StdEncoding.EncodeToString(privBytes),
	}
	return id, nil
}

// KEMKey retrieves the full KEM key pair for the given label.
// Returns ErrKeyRetired if the key has been rotated.
func (s *Store) KEMKey(label string) (*pqc.HybridKeyPair, error) {
	e, err := s.getEntry(label, KEMKey)
	if err != nil {
		return nil, err
	}
	if e.Status == Retired {
		return nil, ErrKeyRetired
	}
	privBytes, err := base64.StdEncoding.DecodeString(e.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidData, err)
	}
	return pqc.UnmarshalKeyPair(privBytes)
}

// SigningKey retrieves the full signing key pair for the given label.
// Returns ErrKeyRetired if the key has been rotated.
func (s *Store) SigningKey(label string) (*sign.HybridSigningKeyPair, error) {
	e, err := s.getEntry(label, SigningKey)
	if err != nil {
		return nil, err
	}
	if e.Status == Retired {
		return nil, ErrKeyRetired
	}
	privBytes, err := base64.StdEncoding.DecodeString(e.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidData, err)
	}
	return sign.UnmarshalKeyPair(privBytes)
}

// KEMPublicKey retrieves the KEM public key for the given label.
// Works for retired keys too, allowing decryption of old data.
func (s *Store) KEMPublicKey(label string) (*pqc.HybridPublicKey, error) {
	e, err := s.getEntry(label, KEMKey)
	if err != nil {
		return nil, err
	}
	pubBytes, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidData, err)
	}
	return pqc.UnmarshalPublicKey(pubBytes)
}

// SigningPublicKey retrieves the signing public key for the given label.
// Works for retired keys too.
func (s *Store) SigningPublicKey(label string) (*sign.HybridPublicKey, error) {
	e, err := s.getEntry(label, SigningKey)
	if err != nil {
		return nil, err
	}
	pubBytes, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidData, err)
	}
	return sign.UnmarshalPublicKey(pubBytes)
}

// List returns a summary of all stored keys, sorted by label.
// No key material is included.
func (s *Store) List() []KeyInfo {
	infos := make([]KeyInfo, 0, len(s.data.Entries))
	for _, e := range s.data.Entries {
		infos = append(infos, KeyInfo{
			ID:      e.ID,
			Label:   e.Label,
			Type:    e.Type,
			Status:  e.Status,
			Created: e.Created,
			Rotated: e.Rotated,
			Version: e.Version,
		})
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Label < infos[j].Label
	})
	return infos
}

// Rotate retires the current key and generates a new one under the same label.
// The old key is moved to "label@vN" with status retired.
// Returns the new key's unique ID.
func (s *Store) Rotate(label string) (string, error) {
	old, ok := s.data.Entries[label]
	if !ok {
		return "", ErrNotFound
	}
	if old.Status == Retired {
		return "", ErrKeyRetired
	}

	oldVersion := old.Version
	oldType := old.Type

	// Move old entry to versioned label.
	versionedLabel := fmt.Sprintf("%s@v%d", label, oldVersion)
	old.Label = versionedLabel
	old.Status = Retired
	old.Rotated = time.Now().UTC()
	s.data.Entries[versionedLabel] = old
	delete(s.data.Entries, label)

	// Generate new key of the same type.
	var id string
	var err error
	switch oldType {
	case KEMKey:
		id, err = s.GenerateKEMKey(label)
	case SigningKey:
		id, err = s.GenerateSigningKey(label)
	default:
		return "", fmt.Errorf("keystore: unknown key type %q", oldType)
	}
	if err != nil {
		return "", err
	}

	// Set the correct version on the new entry.
	s.data.Entries[label].Version = oldVersion + 1
	return id, nil
}

// Delete removes a key from the store.
func (s *Store) Delete(label string) error {
	if _, ok := s.data.Entries[label]; !ok {
		return ErrNotFound
	}
	delete(s.data.Entries, label)
	return nil
}

func (s *Store) getEntry(label string, expectedType KeyType) (*keyEntry, error) {
	e, ok := s.data.Entries[label]
	if !ok {
		return nil, ErrNotFound
	}
	if e.Type != expectedType {
		return nil, ErrTypeMismatch
	}
	return e, nil
}

func validateLabel(label string) error {
	if label == "" {
		return ErrEmptyLabel
	}
	if strings.Contains(label, "@") {
		return errors.New("keystore: label must not contain '@'")
	}
	return nil
}

func deriveKey(password, salt []byte) ([]byte, error) {
	return kdf.Argon2id(password, salt, 3, 64*1024, 4, 32)
}

package users

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHash represents a hashed password.
type PasswordHash struct {
	Hash      string
	Algorithm string
}

// String converts the PasswordHash to a string for storage.
func (p *PasswordHash) String() string {
	js, _ := json.Marshal(p)
	return base64.StdEncoding.EncodeToString(js)
}

// PasswordHashParse parses a string into a PasswordHash.
func PasswordHashParse(s string) (*PasswordHash, error) {
	js, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	var p PasswordHash
	if err := json.Unmarshal(js, &p); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	return &p, nil
}

// PasswordHashDefault hashes the password using the default algorithm. This
// is equivalent to PasswordHashBcrypt.
func PasswordHashDefault(password string) (*PasswordHash, error) {
	return PasswordHashBcrypt(password)
}

// PasswordHashBcrypt hashes the password using the bcrypt algorithm.
func PasswordHashBcrypt(password string) (*PasswordHash, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt: %w", err)
	}
	return &PasswordHash{
		Hash:      string(hash),
		Algorithm: "bcrypt",
	}, nil
}

// Verify checks if the password matches the hash.
func (p *PasswordHash) Verify(password string) error {
	switch p.Algorithm {
	case "bcrypt":
		if err := bcrypt.CompareHashAndPassword([]byte(p.Hash), []byte(password)); err != nil {
			return fmt.Errorf("%w: %s", ErrPasswordHashMismatch, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrPasswordHashUnknownAlgorithm, p.Algorithm)
	}
}

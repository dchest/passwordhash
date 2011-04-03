// Package passwordhash implements safe password hashing and comparison.
//
// Passwords are derived using PBKDF2-SHA256 function with 5000 iterations (by default), 
// with 32-byte salt and 64-byte output.
package passwordhash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/dchest/pbkdf2"
)

// PasswordHash represents storage for password hash and salt.
type PasswordHash struct {
	Iterations int
	Salt       []byte
	Hash       []byte
}

const (
	// Default number of iterations for PBKDF2.
	DefaultIterations = 5000
	// Default salt length.
	SaltLen = 32
)

// getSalt returns a new random salt.
func getSalt() []byte {
	salt := make([]byte, SaltLen)
	if _, err := rand.Reader.Read(salt); err != nil {
		panic("can't read from random source: " + err.String())
	}
	return salt
}

// New returns a new password hash derived from the provided password, 
// a random salt, and the default number of iterations.
func New(password string) *PasswordHash {
	return NewWithSaltIterations(password, getSalt(), DefaultIterations)
}

// NewWithIterations returns a new password hash derived from the provided
// password, number of iterations, and a random salt.
func NewWithIterations(password string, iterations int) *PasswordHash {
	return NewWithSaltIterations(password, getSalt(), iterations)
}

// NewWithSaltIterations creates a new password hash from the provided password, salt,
// and the number of iterations.
func NewWithSaltIterations(password string, salt []byte, iterations int) *PasswordHash {
	return &PasswordHash{iterations, salt,
		pbkdf2.PBKDF2([]byte(password), salt, iterations, sha256.New, 64)}
}

// EqualToPassword returns true if the password hash was derived from the provided password.
// This function uses constant time comparison.
func (ph *PasswordHash) EqualToPassword(password string) bool {
	provided := NewWithSaltIterations(password, ph.Salt, ph.Iterations)
	return subtle.ConstantTimeCompare(ph.Hash, provided.Hash) == 1
}

// String returns a string representation of the password hash.
func (ph *PasswordHash) String() string {
	return fmt.Sprintf("&PasswordHash{Iterations: %d, Salt: %x, Hash: %x}",
		ph.Iterations, ph.Salt, ph.Hash)
}

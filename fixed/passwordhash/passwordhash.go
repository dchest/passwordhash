// Package passwordhash implements safe password hashing and comparison.
//
// THIS PACKAGE IS DEPRECATED. SEE README.
//
// Hashes are derived using PBKDF2-HMAC-SHA256 function with 100000 iterations
// (by default), 32-byte salt and 32-byte output.
//
// This packaged is a fixed version of "passwordhash" which uses only 32 bytes
// of hash for comparison.
//
// Note: you must not allow users to change parameters of PasswordHash, such as
// the number of iterations, directly. If a malicious user can change the
// number of iterations, he can set it too high, and it will lead to DoS.
//
// Example usage:
//
//	ph := passwordhash.New("hello, world")
//	// Store ph somewhere...
//	// Later, when user provides a password:
//	if ph.EqualToPassword("hello, world") {
//		// Password's okay, user authorized...
//	}
//
package passwordhash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"code.google.com/p/go.crypto/pbkdf2"
)

// PasswordHash stores hash, salt, and number of iterations.
type PasswordHash struct {
	Iter int
	Salt []byte
	Hash []byte
}

const (
	// Default number of iterations for PBKDF2
	DefaultIterations = 100000
	// Default salt length
	SaltLen = 32
	// Default hash length. This length is also used for hash comparison
	// irregardless of the actual hash length.
	HashLen = 32
)

// getSalt returns a new random salt.
// The function causes runtime panic if it fails to read from random source.
func getSalt() []byte {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic("error reading from random source: " + err.Error())
	}
	return salt
}

// New returns a new password hash derived from the provided password,
// a random salt, and the default number of iterations.
// The function causes runtime panic if it fails to get random salt.
func New(password string) *PasswordHash {
	return NewSaltIter(password, getSalt(), DefaultIterations)
}

// NewIter returns a new password hash derived from the provided password,
// the number of iterations, and a random salt.
// The function causes runtime panic if it fails to get random salt.
func NewIter(password string, iter int) *PasswordHash {
	return NewSaltIter(password, getSalt(), iter)
}

// NewSaltIter creates a new password hash from the provided password, salt,
// and the number of iterations.
func NewSaltIter(password string, salt []byte, iter int) *PasswordHash {
	return &PasswordHash{iter, salt,
		pbkdf2.Key([]byte(password), salt, iter, HashLen, sha256.New)}
}

// EqualToPassword returns true if the password hash was derived from the provided password.
// This function uses constant time comparison.
//
// IMPORTANT: To work around the 2x speedup attack, this function compares only
// the first 32 bytes of the given password hash.
func (ph *PasswordHash) EqualToPassword(password string) bool {
	provided := NewSaltIter(password, ph.Salt, ph.Iter)
	if len(ph.Hash) < HashLen {
		return false
	}
	if len(provided.Hash) != HashLen {
		return false
	}
	return subtle.ConstantTimeCompare(ph.Hash[:HashLen], provided.Hash) == 1
}

// String returns a string representation of the password hash.
func (ph *PasswordHash) String() string {
	return fmt.Sprintf("&PasswordHash{Iter: %d, Salt: %x, Hash: %x}",
		ph.Iter, ph.Salt, ph.Hash)
}

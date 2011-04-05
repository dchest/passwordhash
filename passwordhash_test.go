package passwordhash

import (
	"bytes"
	"testing"
)

func TestNewAndEqualToPassword(t *testing.T) {
	p := New("hello, world")
	if p.Iter != DefaultIterations {
		t.Errorf("Iterations: expected %d, got %d", DefaultIterations, p.Iter)
	}
	if len(p.Hash) != HashLen {
		t.Errorf("Hash length: expected %d, got %d", HashLen, len(p.Hash))
	}
	if len(p.Salt) != SaltLen {
		t.Errorf("Salt length: expected %d, got %d", SaltLen, len(p.Salt))
	}
	if !p.EqualToPassword("hello, world") {
		t.Errorf("passwords are not equal, expected equal")
	}
	if p.EqualToPassword("different one") {
		t.Errorf("passwords are equal, expected not equal")
	}
}

func TestNewSaltIter(t *testing.T) {
	// Test hash for password "password" and salt "salt"
	testHash := []byte{0x8f, 0xc2, 0xbc, 0xff, 0xbb, 0x4b, 0x1a, 0xc9,
		0xb9, 0xde, 0x03, 0x58, 0x8d, 0x39, 0x0f, 0x3d, 0x9b, 0xf3,
		0x36, 0xc2, 0xc4, 0x42, 0x2c, 0x90, 0xc1, 0x58, 0xcc, 0x71,
		0x42, 0x25, 0xf6, 0x29, 0x06, 0x81, 0x2b, 0x32, 0xcd, 0xa6,
		0xe2, 0xdc, 0xbd, 0x64, 0xad, 0x54, 0x08, 0x03, 0x80, 0x90,
		0x93, 0x53, 0x8a, 0x46, 0xe7, 0x10, 0x40, 0x9a, 0xe2, 0xca,
		0x54, 0x88, 0xab, 0x0e, 0x7d, 0x07}
	ph := NewSaltIter("password", []byte("salt"), DefaultIterations)
	if !bytes.Equal(ph.Hash, testHash) {
		t.Errorf("wrong hash: expected %x, got %x", testHash, ph.Hash)
	}
}

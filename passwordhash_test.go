package passwordhash

import (
	"testing"
)

const (
	saltLen = 32
	hashLen = 64
)

func TestPasswordHash(t *testing.T) {
	p := New("hello, world")
	if p.Iterations != DefaultIterations {
		t.Errorf("Iterations: expected %d, got %d", DefaultIterations, p.Iterations)
	}
	if len(p.Hash) != hashLen {
		t.Errorf("Hash length: expected %d, got %d", hashLen, len(p.Hash))
	}
	if len(p.Salt) != saltLen {
		t.Errorf("Salt length: expected %d, got %d", saltLen, len(p.Salt))
	}
	if !p.EqualToPassword("hello, world") {
		t.Errorf("passwords are not equal, expected equal")
	}
	if p.EqualToPassword("different one") {
		t.Errorf("passwords are equal, expected not equal")
	}
}

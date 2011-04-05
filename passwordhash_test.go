package passwordhash

import (
	"testing"
)

func TestPasswordHash(t *testing.T) {
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

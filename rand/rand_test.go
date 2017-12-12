package rand

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/LoCCS/lmots"
)

// TestRand tests the correctness of Rand
func TestRand(t *testing.T) {
	seed := make([]byte, lmots.N)
	_, err := rand.Read(seed)
	if nil != err {
		t.Fatal(err)
	}

	rng := New(seed)
	// update seed
	rng.Read(nil)
	if bytes.Equal(seed, rng.Seed()) {
		t.Fatal("seed should have been updated")
	}

	rng2 := New(rng.Seed())

	p := make([]byte, lmots.N)
	p2 := make([]byte, lmots.N)

	for i := 0; i < 8; i++ {
		rng.Read(p)
		rng2.Read(p2)

		if !bytes.Equal(p, p2) {
			t.Fatalf("wants %x, got %x", p, p2)
		}
	}
}

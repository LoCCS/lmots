package rand

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/sha3"
)

// Reader is a globally accessible PRNG (pseudo random number generator) instance
var Reader io.Reader

// init initializes the globally accessible PRNG
func init() {
	seed := make([]byte, 32)
	// ignore error
	rand.Read(seed)

	Reader = New(seed)
}

// Rand implements a PRNG based on a sha3.ShakeHash
// every read from which will update the internal seed as
// seed := hash(seed)
type Rand struct {
	seed []byte // state seed
	sha  sha3.ShakeHash
}

// New makes PRNG instance based on the given seed
func New(seed []byte) *Rand {
	rng := new(Rand)
	rng.Init(seed)

	return rng
}

// Init resets the PRNG with the provided seed
// so as to recover it to a deterministic state
func (rng *Rand) Init(seed []byte) {
	rng.seed = nil
	rng.seed = make([]byte, len(seed))
	copy(rng.seed, seed)

	if nil == rng.sha {
		rng.sha = sha3.NewShake256()
	}
}

// Read reads out len(p) random bytes
// and update the underlying state seed
func (rng *Rand) Read(p []byte) (int, error) {
	rng.sha.Reset()
	rng.sha.Write(rng.seed)

	// update seed
	rng.sha.Read(rng.seed)
	// read out random bytes
	return rng.sha.Read(p)
}

// Seed exports the seed for next generation
func (rng *Rand) Seed() []byte {
	seed := make([]byte, len(rng.seed))
	copy(seed, rng.seed)

	return seed
}

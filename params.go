package lmots

import (
	"math"

	"golang.org/x/crypto/sha3"
)

// N is the security level measured in the bytes length
// of output of the hash function in use
const N = 32

// typecodes as prefix secret key, public key and signature
const (
	LMOTS_SHAKE256_N32_W2 = iota
	LMOTS_SHAKE256_N32_W4
)

type LMOTSOpts struct {
	typecode uint8
	// the number of bytes of the output of the hash function
	n uint8
	// the width (in bits) of the Winternitz coefficients
	// it is a member of the set { 1, 2, 4, 8 }
	w uint8
	// Winternitz mask: (1<<w)-1
	//wtnMask uint8
	// the number of independent Winternitz chains used in the signature
	p uint8
	// the number of left-shift bits used in the checksum function
	ls uint8
	// a SHAKE variant version of SHA3
	sha sha3.ShakeHash
	// key identifier: leave empty now
	II [16]byte
}

func newLMOTSOpts(typecode uint8) *LMOTSOpts {
	opts := new(LMOTSOpts)
	opts.typecode = typecode

	switch typecode {
	case LMOTS_SHAKE256_N32_W2:
		opts.n = 32
		opts.w = 2
	case LMOTS_SHAKE256_N32_W4:
		opts.n = 32
		opts.w = 4
	default:
		panic("invalid typecode")
	}

	wtnMask := uint16((1 << opts.w) - 1)

	// extend range to avoid overflow
	n := uint16(opts.n)
	w := uint16(opts.w)

	u := (8*n + w - 1) / w
	v := uint16(math.Log2(float64(wtnMask*u))/float64(w)) + 1

	opts.p = uint8(u + v)
	opts.ls = uint8(16 - v*w)

	opts.sha = sha3.NewShake256()

	return opts
}

// LMOTS_SHAKE256_N32_W2_OPTS: specialized options for n=32, w=2
// LMOTS_SHAKE256_N32_W4_OPTS: specialized options for n=32, w=4
// users should only run the library with one of these provided options
// otherwise, the correctness of the implementation is unpredictable
var LMOTS_SHAKE256_N32_W2_OPTS, LMOTS_SHAKE256_N32_W4_OPTS *LMOTSOpts

func init() {
	LMOTS_SHAKE256_N32_W2_OPTS = newLMOTSOpts(LMOTS_SHAKE256_N32_W2)
	LMOTS_SHAKE256_N32_W4_OPTS = newLMOTSOpts(LMOTS_SHAKE256_N32_W4)
}

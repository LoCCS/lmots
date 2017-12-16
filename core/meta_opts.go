package lmots

import (
	"encoding/binary"
	"math"

	"github.com/LoCCS/lmots"
)

type MetaOpts struct {
	typecode [4]byte
	// the number of bytes of the output of the hash function
	n uint8
	// the width (in bits) of the Winternitz coefficients
	// it is a member of the set { 1, 2, 4, 8 }
	w uint8
	// the number of independent Winternitz chains used in the signature
	p uint8
	// the number of left-shift bits used in the checksum function
	ls uint8
}

func newMetaOpts(typecode uint8) *MetaOpts {
	opts := new(MetaOpts)

	switch typecode {
	case lmots.LMOTS_SHAKE256_N32_W2:
		opts.n = 32
		opts.w = 2
	case lmots.LMOTS_SHAKE256_N32_W4:
		opts.n = 32
		opts.w = 4
	default:
		panic("invalid typecode")
	}
	binary.BigEndian.PutUint32(opts.typecode[:], uint32(typecode))

	wtnMask := uint16((1 << opts.w) - 1)

	// extend range to avoid overflow
	n := uint16(opts.n)
	w := uint16(opts.w)

	u := (8*n + w - 1) / w
	v := uint16(math.Log2(float64(wtnMask*u))/float64(w)) + 1

	opts.p = uint8(u + v)
	opts.ls = uint8(16 - v*w)

	//opts.sha = sha3.NewShake256()

	return opts
}

// METAOPTS_SHAKE256_N32_W2: specialized options for n=32, w=2
// METAOPTS_SHAKE256_N32_W4: specialized options for n=32, w=4
// users should only run the library with one of these provided options
// otherwise, the correctness of the implementation is unpredictable
// ALL THESE OPTIONS SHOULD BE **READONLY**
var METAOPTS_SHAKE256_N32_W2, METAOPTS_SHAKE256_N32_W4 *MetaOpts

// this one is set as default in current implementation
var METAOPTS_DEFAULT *MetaOpts

func init() {
	METAOPTS_SHAKE256_N32_W2 = newMetaOpts(lmots.LMOTS_SHAKE256_N32_W2)
	METAOPTS_SHAKE256_N32_W4 = newMetaOpts(lmots.LMOTS_SHAKE256_N32_W4)

	METAOPTS_DEFAULT = METAOPTS_SHAKE256_N32_W4
}

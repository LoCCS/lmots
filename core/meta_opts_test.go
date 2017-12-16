package lmots

import (
	"bytes"
	"testing"

	"github.com/LoCCS/lmots"
)

func TestMetaOpts(t *testing.T) {
	optsVecWanted := []*MetaOpts{
		{
			typecode: [4]byte{0, 0, 0, lmots.LMOTS_SHAKE256_N32_W2},
			n:        32,
			w:        2,
			p:        133,
			ls:       6,
		},
		{
			typecode: [4]byte{0, 0, 0, lmots.LMOTS_SHAKE256_N32_W4},
			n:        32,
			w:        4,
			p:        67,
			ls:       4,
		},
	}
	optsVec2Test := []*MetaOpts{METAOPTS_SHAKE256_N32_W2, METAOPTS_SHAKE256_N32_W4}

	for i := range optsVec2Test {
		if !bytes.Equal(optsVec2Test[i].typecode[:], optsVecWanted[i].typecode[:]) {
			t.Fatalf("invalid typecode: want %x, got %x",
				optsVecWanted[i].typecode[:], optsVec2Test[i].typecode[:])
		}
		if optsVec2Test[i].n != optsVecWanted[i].n {
			t.Fatalf("invalid output length of hash functions")
		}
		if optsVec2Test[i].w != optsVecWanted[i].w {
			t.Fatalf("invalid Winternitz parameters")
		}
		if optsVec2Test[i].p != optsVecWanted[i].p {
			t.Fatalf("invalid number of Winternitz chains")
		}
		if optsVec2Test[i].ls != optsVecWanted[i].ls {
			t.Fatalf("invalid number of bits to shift")
		}
	}
}

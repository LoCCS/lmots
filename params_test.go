package lmots

import "testing"

func TestLMOTSOpts(t *testing.T) {
	optsVecWanted := []*LMOTSOpts{
		{
			typecode: LMOTS_SHAKE256_N32_W2,
			n:        32,
			w:        2,
			p:        133,
			ls:       6,
		},
		{
			typecode: LMOTS_SHAKE256_N32_W4,
			n:        32,
			w:        4,
			p:        67,
			ls:       4,
		},
	}
	optsVec2Test := []*LMOTSOpts{LMOTS_SHAKE256_N32_W2_OPTS, LMOTS_SHAKE256_N32_W4_OPTS}

	for i := range optsVec2Test {
		if optsVec2Test[i].typecode != optsVecWanted[i].typecode {
			t.Fatalf("invalid typecode")
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

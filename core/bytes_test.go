package lmots

import "testing"

func TestCoef(t *testing.T) {
	S := []byte{0x12, 0x34, 0x56, 0x78}
	const w = 4
	ell := uint16(8 / w * len(S))

	wants := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for i := uint16(0); i < ell; i++ {
		c := coef(S, i, w)
		if c != wants[i] {
			t.Fatalf("wrong %v-th coef: wants %v, got %v", i, wants[i], c)
		}
	}
}

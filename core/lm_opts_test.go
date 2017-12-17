package lmots

import "testing"

func TestLMOpts(t *testing.T) {
	opts := &LMOpts{
		typecode: [4]byte{1, 2, 3, 4},
		keyIdx:   0x1234,
	}

	optsC := opts.Clone()
	optsC.typecode[2] = 0x56

	if optsC.typecode[2] == opts.typecode[2] {
		t.Fatalf("want %v, got %v", opts.typecode[2], optsC.typecode[2])
	}
}

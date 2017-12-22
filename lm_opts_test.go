package lmots

import (
	"bytes"
	"testing"
)

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

func TestLMOptsSerialize(t *testing.T) {
	opts := NewLMOpts()
	opts.keyIdx = 0x1234
	opts.I[2] = 0x56

	buf := opts.Serialize()

	opts2 := new(LMOpts)
	opts2.Deserialize(buf)

	if !bytes.Equal(opts.typecode[:], opts2.typecode[:]) {
		t.Fatalf("invalid typecode: want %x, got %x",
			opts.typecode[:], opts2.typecode[:])
	}

	if !bytes.Equal(opts.I[:], opts2.I[:]) {
		t.Fatalf("invalid key id: want %x, got %x",
			opts.I[:], opts2.I[:])

	}

	if opts.keyIdx != opts2.keyIdx {
		t.Fatalf("invalid key index: want %v, got %v",
			opts.keyIdx, opts2.keyIdx)
	}
}

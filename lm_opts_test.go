package lmots

import (
	"bytes"
	"encoding/gob"
	"testing"
)

func TestLMOpts(t *testing.T) {
	opts := &LMOpts{
		Typecode: [4]byte{1, 2, 3, 4},
		KeyIdx:   0x1234,
	}

	optsC := opts.Clone()
	optsC.Typecode[2] = 0x56

	if optsC.Typecode[2] == opts.Typecode[2] {
		t.Fatalf("want %v, got %v", opts.Typecode[2], optsC.Typecode[2])
	}
}

func TestLMOptsEncoding(t *testing.T) {
	opts := NewLMOpts()
	opts.KeyIdx = 0x1234
	opts.I[2] = 0x56

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(opts); nil != err {
		t.Fatal(err)
	}

	opts2 := new(LMOpts)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(opts2); nil != err {
		t.Fatal(err)
	}

	if !bytes.Equal(opts.Typecode[:], opts2.Typecode[:]) {
		t.Fatalf("invalid typecode: want %x, got %x",
			opts.Typecode[:], opts2.Typecode[:])
	}

	if !bytes.Equal(opts.I[:], opts2.I[:]) {
		t.Fatalf("invalid key id: want %x, got %x",
			opts.I[:], opts2.I[:])

	}

	if opts.KeyIdx != opts2.KeyIdx {
		t.Fatalf("invalid key index: want %v, got %v",
			opts.KeyIdx, opts2.KeyIdx)
	}
}

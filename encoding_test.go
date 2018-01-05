package lmots

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"testing"
)

func TestLMOptsEncoding(t *testing.T) {
	opts := NewLMOpts()
	opts.keyIdx = 0x1234
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

func TestSigEncoding(t *testing.T) {
	// make a dummy sig
	sig := new(Sig)
	if _, err := rand.Read(sig.typecode[:]); nil != err {
		t.Fatal(err)
	}

	sig.C = make([]byte, 32)
	if _, err := rand.Read(sig.C); nil != err {
		t.Fatal(err)
	}

	sig.sigma = make([]HashType, 16)
	for i := range sig.sigma {
		sig.sigma[i] = make(HashType, 16)

		if _, err := rand.Read(sig.sigma[i]); nil != err {
			t.Fatal(err)
		}
	}

	// decode the dummy sig
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(sig); nil != err {
		t.Fatal(err)
	}

	dec := gob.NewDecoder(buf)
	sigC := new(Sig)
	if err := dec.Decode(sigC); nil != err {
		t.Fatal(err)
	}

	// check typecode
	if !bytes.Equal(sig.typecode[:], sigC.typecode[:]) {
		t.Fatalf("mismatch typecode: want %x, got %x", sig.typecode[:], sigC.typecode[:])
	}
	// check randomizer
	if !bytes.Equal(sig.C, sigC.C) {
		t.Fatalf("mismatch C: want %x, got %x", sig.C, sigC.C)
	}
	// check sigma
	if len(sig.sigma) != len(sigC.sigma) {
		t.Fatalf("mismatch len(sigma): want %v, got %v", len(sig.sigma), len(sigC.sigma))
	}
	// check sigma[i]
	for i := range sig.sigma {
		if !bytes.Equal(sig.sigma[i], sigC.sigma[i]) {
			t.Fatalf("mismatch sigma[%v], want %x, got %x", i, sig.sigma[i], sigC.sigma[i])
		}
	}

	//t.Logf("%+v\n", sig)
	//t.Logf("%+v\n", sigC)
}

package lmots

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"testing"

	lmrand "github.com/LoCCS/lmots/rand"
)

func TestPkEncoding(t *testing.T) {
	dummyOpts := NewLMOpts()
	sk, _ := GenerateKey(dummyOpts, lmrand.Reader)

	pk := &sk.PublicKey
	pk.KeyIdx = 0x1234

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(pk); nil != err {
		t.Fatal(err)
	}

	pk2 := new(PublicKey)
	pk2.LMOpts = new(LMOpts)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(pk2); nil != err {
		t.Fatal(err)
	}

	if !pk.Equal(pk2) {
		t.Fatal("the decoded pubkey is invalid")
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

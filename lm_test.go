package lmots

import (
	"testing"

	"github.com/LoCCS/lmots/rand"
	"golang.org/x/crypto/sha3"
)

func TestLMSig(t *testing.T) {
	hash := sha3.Sum256([]byte("hello Leighton-Micali Signature"))

	dummyOpts := new(LMOpts)
	dummyOpts.Typecode = METAOPTS_DEFAULT.typecode
	sk, _ := GenerateKey(dummyOpts, rand.Reader)

	sig, err := Sign(rand.Reader, sk, hash[:])
	if nil != err {
		t.Fatal(err)
	}

	if !Verify(&sk.PublicKey, hash[:], sig) {
		t.Fatal("verification failed")
	}
}

func TestLMSigBadPk(t *testing.T) {
	hash := sha3.Sum256([]byte("hello Leighton-Micali Signature"))

	dummyOpts := new(LMOpts)
	dummyOpts.Typecode = METAOPTS_DEFAULT.typecode
	sk, _ := GenerateKey(dummyOpts, rand.Reader)

	sig, err := Sign(rand.Reader, sk, hash[:])
	if nil != err {
		t.Fatal(err)
	}

	sk.PublicKey.K[1] = ^sk.PublicKey.K[1]

	if Verify(&sk.PublicKey, hash[:], sig) {
		t.Fatal("verification failed")
	}
}

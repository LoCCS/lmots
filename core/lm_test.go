package lmots

import (
	"testing"

	lmotsrand "github.com/LoCCS/lmots/rand"
	"golang.org/x/crypto/sha3"
)

func TestLMSig(t *testing.T) {
	hash := sha3.Sum256([]byte("hello Leighton-Micali Signature"))

	dummyOpts := new(LMOpts)
	dummyOpts.typecode = METAOPTS_DEFAULT.typecode
	sk, _ := GenerateKey(dummyOpts, lmotsrand.Reader)

	sig, err := Sign(lmotsrand.Reader, sk, hash[:])
	if nil != err {
		t.Fatal(err)
	}

	if !Verify(&sk.PublicKey, hash[:], sig) {
		t.Fatal("verification failed")
	}
}
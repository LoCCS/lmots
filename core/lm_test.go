package lmots

import (
	"testing"

	lmotsrand "github.com/LoCCS/lmots/rand"
	"golang.org/x/crypto/sha3"
)

func TestLMSig(t *testing.T) {
	hash := sha3.Sum256([]byte("hello Leighton-Micali Signature"))

	//t.Logf("%x\n", hash[:])
	dummyOpts := new(LMOpts)
	dummyOpts.typecode = METAOPTS_DEFAULT.typecode
	//t.Logf("%+v\n", dummyOpts)
	sk, _ := GenerateKey(dummyOpts, lmotsrand.Reader)
	//t.Logf("%v\n", sk)

	sig, err := Sign(lmotsrand.Reader, sk, hash[:])
	if nil != err {
		t.Fatal(err)
	}

	if !Verify(&sk.PublicKey, hash[:], sig) {
		t.Fatal("verification failed")
	}
}

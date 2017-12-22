package lmots

import (
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/LoCCS/lmots/rand"
)

func BenchmarkGenerateKey(b *testing.B) {
	dummyOpts := new(LMOpts)
	for i := 0; i < b.N; i++ {
		GenerateKey(dummyOpts, rand.Reader)
	}
}

func BenchmarkLMSStdOps(b *testing.B) {
	msg := sha3.Sum256([]byte("helo Leighton-Micali Signatures"))

	dummyOpts := new(LMOpts)
	dummyOpts.typecode = METAOPTS_DEFAULT.typecode
	for i := 0; i < b.N; i++ {
		dummyOpts.SetKeyIdx(uint32(i))
		sk, err := GenerateKey(dummyOpts, rand.Reader)

		sig, err := Sign(rand.Reader, sk, msg[:])
		if nil != err {
			b.Fatal(err)
		}

		if !Verify(&sk.PublicKey, msg[:], sig) {
			b.Fatal("verification failed")
		}
	}
}

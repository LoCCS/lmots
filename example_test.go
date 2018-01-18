package lmots

import (
	"crypto/rand"
	"fmt"

	mathrand "math/rand"

	"golang.org/x/crypto/sha3"
)

// ExampleLMS demonstrates the usage of this lib
func ExampleLMS() {
	msg := sha3.Sum256([]byte("Hello Leighton-Micali Signatures"))

	dummyOpts := &LMOpts{
		Typecode: METAOPTS_DEFAULT.typecode,
		KeyIdx:   mathrand.Uint32(),
	}

	if _, err := rand.Read(dummyOpts.I[:]); nil != err {
		panic(err)
	}

	sk, err := GenerateKey(dummyOpts, rand.Reader)
	if nil != err {
		panic(err)
	}

	sig, err := Sign(rand.Reader, sk, msg[:])
	if nil != err {
		panic(err)
	}

	fmt.Println(Verify(&sk.PublicKey, msg[:], sig))
	// Output: true
}

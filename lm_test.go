package lmots

import (
	"bytes"
	cryptorand "crypto/rand"
	mathrand "math/rand"
	"testing"

	"github.com/LoCCS/lmots/rand"
	"golang.org/x/crypto/sha3"
)

func mockUpLMS() (HashType, *PrivateKey, *Sig, error) {
	hash := sha3.Sum256([]byte("Hello Leighton-Micali Signature"))

	dummyOpts := new(LMOpts)
	dummyOpts.Typecode = METAOPTS_DEFAULT.typecode
	cryptorand.Read(dummyOpts.I[:])
	dummyOpts.KeyIdx = mathrand.Uint32()
	sk, _ := GenerateKey(dummyOpts, rand.Reader)

	sig, err := Sign(rand.Reader, sk, hash[:])

	return hash[:], sk, sig, err
}

func flipOneByte(x []byte) {
	if nil == x {
		return
	}

	i := mathrand.Uint32() % uint32(len(x))
	x[i] = ^x[i]
}

func TestRecoverK(t *testing.T) {
	msg, sk, sig, err := mockUpLMS()
	if nil != err {
		t.Fatal(err)
	}

	Kc, err := RecoverK(sk.PublicKey.Opts, msg, sig)
	if nil != err {
		t.Fatal(err)
	}

	if !bytes.Equal(sk.PublicKey.K, Kc) {
		t.Fatal("the recovered public key is invalid")
	}
	//t.Logf("%x\n", sk.PublicKey.K)
	//t.Logf("%x\n", Kc)
}

func TestLMSFull(t *testing.T) {
	hash, sk, sig, err := mockUpLMS()
	if nil != err {
		t.Fatal(err)
	}

	okTest := func(t *testing.T) {
		if !Verify(&sk.PublicKey, hash[:], sig) {
			t.Fatal("verification failed")
		}
	}

	badPkTest := func(t *testing.T) {
		badPk := (&sk.PublicKey).Clone()
		flipOneByte(badPk.K)

		if Verify(badPk, hash[:], sig) {
			t.Fatal("verification with a bad public key should fail")
		}
	}

	badMsgTest := func(t *testing.T) {
		badHash := make(HashType, len(hash))
		copy(badHash, hash[:])
		flipOneByte(badHash)

		if Verify(&sk.PublicKey, badHash, sig) {
			t.Fatal("verification on a bad message should fail")
		}
	}
	badSigTest := func(t *testing.T) {
		flipOneByte(sig.C)
		if Verify(&sk.PublicKey, hash[:], sig) {
			t.Fatal("verification on a bad signature should fail")
		}
	}

	t.Run("OK", okTest)
	t.Run("Bad Pk", badPkTest)
	t.Run("Bad Msg", badMsgTest)
	t.Run("Bad Sig", badSigTest)
}

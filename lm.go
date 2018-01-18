package lmots

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"sync"

	"github.com/LoCCS/lmots/hash"
)

type HashType = []byte

// PublicKey as container for public key
type PublicKey struct {
	Opts *LMOpts
	K HashType // hash of public key components
}

// Clone makes a copy of this pk
func (pk *PublicKey) Clone() *PublicKey {
	pkC := new(PublicKey)

	pkC.Opts = pk.Opts.Clone()
	if nil != pk.K {
		pkC.K = make(HashType, len(pk.K))
		copy(pkC.K, pk.K)
	}

	return pkC
}

// Equal checks if this `pk` equals to `rhs`
func (pk *PublicKey) Equal(rhs *PublicKey) bool {
	if pk == rhs {
		return true
	}

	return (nil != rhs) &&
		((pk.Opts == rhs.Opts) ||
			((nil != pk.Opts) && (pk.Opts.Equal(rhs.Opts)))) &&
		bytes.Equal(pk.K, rhs.K)
}

// PrivateKey as container for private key,
// it also embeds its corresponding public key
type PrivateKey struct {
	PublicKey
	x []HashType
}

// Equal checks if this key equals to the given one
func (sk *PrivateKey) Equal(rhs *PrivateKey) bool {
	if sk == rhs {
		return true
	}

	return (nil != rhs) && (&sk.PublicKey).Equal(&rhs.PublicKey)
}

// Sig as container for the Winternitz one-time signature
// export all fields to make it encodeable as Gob
type Sig struct {
	Typecode [4]byte
	C        []byte
	Sigma    []HashType
}

// GenerateKey generates a key pair
func GenerateKey(opts *LMOpts, rng io.Reader) (*PrivateKey, error) {
	sk := new(PrivateKey)
	sk.x = make([]HashType, METAOPTS_DEFAULT.p)

	she := hash.NewShakeHashEx()
	{
		seed := make([]byte, METAOPTS_DEFAULT.n)
		rng.Read(seed)

		for j := range sk.x {
			she.Reset()
			// I
			she.Write(opts.I[:])
			// q
			she.WriteUint32(opts.KeyIdx)
			// j
			she.WriteUint16(uint16(j))
			// dummy byte
			she.WriteUint8(0xff)
			// seed
			she.Write(seed)

			// read out sk[j]
			sk.x[j] = make(HashType, METAOPTS_DEFAULT.n)
			she.Read(sk.x[j])
		}
	}

	// evaluate the corresponding public key
	sk.PublicKey.Opts = opts.Clone()

	Ys := make([]HashType, METAOPTS_DEFAULT.p)
	var numItr uint8 = (1 << METAOPTS_DEFAULT.w) - 1

	var wg sync.WaitGroup
	numCPU := uint8(runtime.NumCPU())
	jobSize := (METAOPTS_DEFAULT.p + numCPU - 1) / numCPU
	for i := uint8(0); i < numCPU; i++ {
		wg.Add(1)
		// worker
		go func(workerIdx uint8) {
			defer wg.Done()

			// range of chains run by this worker
			from := workerIdx * jobSize
			to := from + jobSize
			if to > METAOPTS_DEFAULT.p {
				to = METAOPTS_DEFAULT.p
			}

			for j := from; j < to; j++ {
				Ys[j] = evalChaining(sk.Opts, uint16(j), 0, numItr, sk.x[j])
			}
		}(i)
	}
	// wait until all y[j] has been computed
	wg.Wait()

	// calculate K
	she.Reset()
	she.Write(sk.Opts.I[:])
	she.WriteUint32(sk.Opts.KeyIdx)
	she.WriteUint16(D_PBLC)
	for j := range Ys {
		she.Write(Ys[j])
	}
	sk.PublicKey.K = make(HashType, METAOPTS_DEFAULT.n)
	she.Read(sk.PublicKey.K)

	return sk, nil
}

// Sign generates the signature for a message digest
func Sign(rng io.Reader, sk *PrivateKey, msg HashType) (*Sig, error) {
	sig := new(Sig)

	// set type of algo
	sig.Typecode = METAOPTS_DEFAULT.typecode
	// fetch a randomizer
	sig.C = make([]byte, METAOPTS_DEFAULT.n)
	if _, err := rng.Read(sig.C); nil != err {
		return nil, errors.New("failed to get a valid randomizer")
	}

	// run the chaining iterations to generate the signature
	sig.Sigma = batchChaining(sk.Opts, sig.C, msg, sk.x, true)

	return sig, nil
}

// Verify checks the signature on msg against the given public key
func Verify(pk *PublicKey, msg HashType, sig *Sig) bool {
	// ensure pktype=sigtype
	if !bytes.Equal(pk.Opts.Typecode[:], sig.Typecode[:]) {
		return false
	}

	Ys := batchChaining(pk.Opts, sig.C, msg, sig.Sigma, false)

	// Kc
	sh := hash.NewShakeHashEx()
	sh.Write(pk.Opts.I[:])
	sh.WriteUint32(pk.Opts.KeyIdx)
	sh.WriteUint16(D_PBLC)
	for j := range Ys {
		sh.Write(Ys[j])
	}
	Kc := make(HashType, METAOPTS_DEFAULT.n)
	sh.Read(Kc)

	return bytes.Equal(Kc, pk.K)
}

// batchChaining evaluates Winternitz chain in batch
func batchChaining(opts *LMOpts, C []byte, msg HashType,
	Zs []HashType, isSigning bool) []HashType {
	// Q
	extMsg := extendMsg(opts, C, msg, METAOPTS_DEFAULT.w, METAOPTS_DEFAULT.ls)

	// lower bound and upper bound
	var lo, hi uint8 = 0, ((1 << METAOPTS_DEFAULT.w) - 1)
	ell := uint8(len(Zs))
	outs := make([]HashType, ell)

	var wg sync.WaitGroup
	numCPU := uint8(runtime.NumCPU())
	//var numCPU uint8 = 1
	jobSize := (ell + numCPU - 1) / numCPU
	for k := uint8(0); k < numCPU; k++ {
		wg.Add(1)
		// worker
		go func(workerIdx uint8) {
			defer wg.Done()
			// range of blocks evaluated by current worker
			from := workerIdx * jobSize
			to := from + jobSize
			if to > ell {
				to = ell
			}

			a, b := lo, hi
			for i := from; i < to; i++ {
				// update the bound of chaining based on the situation
				if isSigning { // signing
					b = coef(extMsg, uint16(i), METAOPTS_DEFAULT.w)
				} else { // verification
					a = coef(extMsg, uint16(i), METAOPTS_DEFAULT.w)
				}
				outs[i] = evalChaining(opts, uint16(i), a, b, Zs[i])
			}
		}(k)
	}
	// wait for all outputs to be ready
	wg.Wait()

	return outs
}

// utilities functions to remove sooner or later
func (sig *Sig) Equal(rhs *Sig) bool {
	if nil == rhs {
		return false
	}
	if sig == rhs {
		return true
	}
	if !bytes.Equal(sig.Typecode[:], rhs.Typecode[:]) {
		return false
	}
	if !bytes.Equal(sig.C, rhs.C) {
		return false
	}

	if len(sig.Sigma) != len(rhs.Sigma) {
		return false
	}

	for i := range sig.Sigma {
		if !bytes.Equal(sig.Sigma[i], rhs.Sigma[i]) {
			return false
		}
	}

	return true
}
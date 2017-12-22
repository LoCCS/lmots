package lmots

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/LoCCS/lmots/hash"
)

type HashType []byte

// PublicKey as container for public key
type PublicKey struct {
	*LMOpts
	K HashType // hash of public key components
}

func (pk *PublicKey) Clone() *PublicKey {
	pkC := new(PublicKey)

	pkC.LMOpts = pk.LMOpts.Clone()
	if nil != pk.K {
		pkC.K = make(HashType, len(pk.K))
		copy(pkC.K, pk.K)
	}

	return pkC
}
func (pk *PublicKey) Equal(rhs *PublicKey) bool {
	if pk == rhs {
		return true
	}

	return (nil != rhs) &&
		((pk.LMOpts == rhs.LMOpts) ||
			((nil != pk.LMOpts) && (pk.LMOpts.Equal(rhs.LMOpts)))) &&
		bytes.Equal(pk.K, rhs.K)
}

// PrivateKey as container for private key,
//	it also embeds its corresponding public key
type PrivateKey struct {
	PublicKey
	x []HashType
}

func (sk *PrivateKey) Equal(rhs *PrivateKey) bool {
	if sk == rhs {
		return true
	}

	return (nil != rhs) && (&sk.PublicKey).Equal(&rhs.PublicKey)
}

// Sig as container for the Winternitz one-time signature
type Sig struct {
	typecode [4]byte
	C        []byte
	sigma    []HashType
}

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
			she.WriteUint32(opts.keyIdx)
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
	sk.PublicKey.LMOpts = opts.Clone()

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
				Ys[j] = evalChaining(sk.LMOpts, uint16(j), 0, numItr, sk.x[j])
			}
		}(i)
	}
	// wait until all y[j] has been computed
	wg.Wait()

	// calculate K
	she.Reset()
	she.Write(sk.I[:])
	she.WriteUint32(sk.keyIdx)
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
	sig.typecode = METAOPTS_DEFAULT.typecode
	// fetch a randomizer
	sig.C = make([]byte, METAOPTS_DEFAULT.n)
	if _, err := rng.Read(sig.C); nil != err {
		return nil, errors.New("failed to get a valid randomizer")
	}

	// run the chaining iterations to generate the signature
	sig.sigma = batchChaining(sk.LMOpts, sig.C, msg, sk.x, true)

	return sig, nil
}

// Verify checks the signature on msg against the given public key
func Verify(pk *PublicKey, msg HashType, sig *Sig) bool {
	// ensure pktype=sigtype
	if !bytes.Equal(pk.typecode[:], sig.typecode[:]) {
		fmt.Printf("mismatched typecode: want %x, got %x\n", pk.typecode[:], sig.typecode[:])
		return false
	}

	Ys := batchChaining(pk.LMOpts, sig.C, msg, sig.sigma, false)

	// Kc
	sh := hash.NewShakeHashEx()
	sh.Write(pk.I[:])
	sh.WriteUint32(pk.keyIdx)
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

	var lo, hi uint8 = 0, ((1 << METAOPTS_DEFAULT.w) - 1)
	ell := uint8(len(Zs))
	outs := make([]HashType, ell)

	var wg sync.WaitGroup
	numCPU := uint8(runtime.NumCPU())
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

			for i := from; i < to; i++ {
				// update the bound of chaining based on the situation
				if isSigning { // signing
					hi = coef(extMsg, uint16(i), METAOPTS_DEFAULT.w)
				} else { // verification
					lo = coef(extMsg, uint16(i), METAOPTS_DEFAULT.w)
				}
				outs[i] = evalChaining(opts, uint16(i), lo, hi, Zs[i])
			}
		}(k)
	}
	// wait for all outputs to be ready
	wg.Wait()

	return outs
}
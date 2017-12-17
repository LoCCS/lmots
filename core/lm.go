package lmots

import (
	"bytes"
	"errors"
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

// PrivateKey as container for private key,
//	it also embeds its corresponding public key
type PrivateKey struct {
	PublicKey
	x []HashType
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

	//fmt.Println("**********keygen")
	//fmt.Printf("I:%x\n", opts.I)
	//fmt.Printf("keyIdx:%v\n", sk.keyIdx)
	// calculate K
	she.Reset()
	she.Write(sk.I[:])
	she.WriteUint32(sk.keyIdx)
	she.WriteUint16(D_PBLC)
	for j := range Ys {
		she.Write(Ys[j])
		//fmt.Printf("Ys[%v]=%x\n", j, Ys[j])
	}
	sk.PublicKey.K = make(HashType, METAOPTS_DEFAULT.n)
	she.Read(sk.PublicKey.K)
	//fmt.Println("**********")

	//fmt.Printf("K: %x\n", sk.PublicKey.K)

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

	// Q
	extMsg := extendMsg(sk.LMOpts, sig.C, msg, METAOPTS_DEFAULT.w, METAOPTS_DEFAULT.ls)
	//fmt.Printf("extMsg: %x\n", extMsg)

	var wg sync.WaitGroup
	numCPU := uint8(runtime.NumCPU())
	ell := uint8(len(sk.x))
	jobSize := (ell + numCPU - 1) / numCPU

	sig.sigma = make([]HashType, ell)
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
				a := coef(extMsg, uint16(i), METAOPTS_DEFAULT.w)
				if 0 == i {
					//fmt.Printf("a0=%v\n", a)
				}
				sig.sigma[i] = evalChaining(sk.LMOpts, uint16(i), 0, a, sk.x[i])
			}
		}(k)
	}

	// synchronise all verification of Y[j]
	wg.Wait()

	return sig, nil
}

func Verify(pk *PublicKey, msg HashType, sig *Sig) bool {
	// ensure pktype=sigtype
	if !bytes.Equal(pk.typecode[:], sig.typecode[:]) {
		//fmt.Printf("pktype: %x, sigtype: %x\n", pk.typecode[:], sig.typecode[:])
		return false
	}

	// Q
	extMsg := extendMsg(pk.LMOpts, sig.C, msg, METAOPTS_DEFAULT.w, METAOPTS_DEFAULT.ls)
	//fmt.Printf("extMsg: %x\n", extMsg)

	var wg sync.WaitGroup
	numCPU := uint8(runtime.NumCPU())
	ell := uint8(len(sig.sigma))
	jobSize := (ell + numCPU - 1) / numCPU

	wtnMask := uint8((1 << METAOPTS_DEFAULT.w) - 1)
	Ys := make([]HashType, ell)

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
				a := coef(extMsg, uint16(i), METAOPTS_DEFAULT.w)
				if 0 == i {
					//fmt.Printf("a0=%v\n", a)
				}
				Ys[i] = evalChaining(pk.LMOpts, uint16(i), a, wtnMask, sig.sigma[i])
			}
		}(k)
	}
	wg.Wait()

	//fmt.Println("*******")
	//fmt.Printf("I: %x\n", pk.I[:])
	//fmt.Printf("keyIdx: %v\n", pk.keyIdx)
	// Kc
	sh := hash.NewShakeHashEx()
	sh.Write(pk.I[:])
	sh.WriteUint32(pk.keyIdx)
	sh.WriteUint16(D_PBLC)
	for j := range Ys {
		sh.Write(Ys[j])
		//fmt.Printf("Ys[%v]=%x\n", j, Ys[j])
	}
	Kc := make(HashType, METAOPTS_DEFAULT.n)
	sh.Read(Kc)
	//fmt.Println("*******")

	//fmt.Printf("K=%x\n", pk.K)
	//fmt.Printf("Kc=%x\n", Kc)

	return bytes.Equal(Kc, pk.K)
}

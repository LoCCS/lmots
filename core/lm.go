package lmots

import (
	"encoding/binary"
	"io"
	"runtime"
	"sync"

	"github.com/LoCCS/lmots/hash"
)

type HashType []byte

// PublicKey as container for public key
type PublicKey struct {
	LMOpts
	Y []byte
}

// PrivateKey as container for private key,
//	it also embeds its corresponding public key
type PrivateKey struct {
	PublicKey
	x []HashType
}

// Sig as container for the Winternitz one-time signature
type Sig struct {
	sigma []HashType
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
	sk.Y = make([]byte, 4+key_id_len+4+METAOPTS_DEFAULT.n)
	offset := 0
	// type
	copy(sk.Y[offset:], METAOPTS_DEFAULT.typecode[:])
	offset += 4
	// I
	copy(sk.Y[offset:], opts.I[:])
	offset += key_id_len
	// q
	binary.BigEndian.PutUint32(sk.Y[offset:], opts.keyIdx)
	offset += 4

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
				Ys[j] = evalChaining(opts.I[:], opts.keyIdx, uint16(j), 0, numItr, sk.x[j])
			}
		}(i)
	}
	// wait until all y[j] has been computed
	wg.Wait()

	// calculate K
	she.Reset()
	she.Write(opts.I[:])
	she.WriteUint32(opts.keyIdx)
	she.WriteUint16(D_PBLC)
	for j := range Ys {
		she.Write(Ys[j])
	}
	she.Read(sk.Y[offset:])

	return sk, nil
}

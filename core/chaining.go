package lmots

import (
	"encoding/binary"

	"github.com/LoCCS/lmots/hash"
)

// evalChaining evaluates the Winternitz chain
// starting from lo to hi (exclusively)
func evalChaining(opts *LMOpts, i uint16,
	lo uint8, hi uint8, data []byte) []byte {

	out := make([]byte, len(data))
	copy(out, data)

	// security prefix: I|q(4)|i(2)|j(1)
	prefix := make([]byte, key_id_len+4+2+1)
	copy(prefix, opts.I[:])
	binary.BigEndian.PutUint32(prefix[key_id_len:], opts.keyIdx)
	binary.BigEndian.PutUint16(prefix[key_id_len+4:], i)

	sh := hash.NewShakeHashEx()
	// offset of iteration index in prefix
	iterIdx := len(prefix) - 1
	for j := lo; j < hi; j++ {
		sh.Reset()
		// out = H(prefix|j|out)
		prefix[iterIdx] = j
		sh.Write(prefix)
		//sh.WriteUint8(j)
		sh.Write(out)

		sh.Read(out)
	}

	return out
}

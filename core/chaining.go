package lmots

import (
	"encoding/binary"

	"github.com/LoCCS/lmots/hash"
)

func evalChaining(opts *LMOpts, i uint16,
	from uint8, to uint8, data []byte) []byte {

	out := make([]byte, len(data))
	copy(out, data)

	// I|q|j
	prefix := make([]byte, key_id_len+4+2)
	copy(prefix, opts.I[:])
	binary.BigEndian.PutUint32(prefix[key_id_len:], opts.keyIdx)
	binary.BigEndian.PutUint16(prefix[key_id_len+4:], i)

	sh := hash.NewShakeHashEx()
	for j := from; j < to; j++ {
		sh.Reset()
		// out = H(prefix|j|out)
		sh.Write(prefix)
		sh.WriteUint8(j)
		sh.Write(out)

		sh.Read(out)
	}

	return out
}

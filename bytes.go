package lmots

import (
	"github.com/LoCCS/lmots/hash"
)

// coef returns the i-th (counting from left)
// w-bit integer parsed from S
func coef(S []byte, i uint16, w uint8) uint8 {
	w16 := uint16(w)
	j := i * w16 / 8

	// number of bit to apply before masking
	bits := 8 - ((i % (8 / w16) * w16) + w16)

	return (((1 << w) - 1) & uint8(S[j]>>bits))
}

// checksum calculates a 2-byte checksum of
// the given hash msg
func checksum(msg []byte, w, ls uint8) []byte {
	var sum uint16

	ell := uint16(len(msg)*8) / uint16(w)
	mask := uint16((1 << w) - 1)
	for i := uint16(0); i < ell; i++ {
		sum += mask - uint16(coef(msg, i, w))
	}

	sum = (sum << ls)
	return []byte{byte((sum >> 8) & 0xff), byte(sum & 0xff)}
}

// extendMsg extends the msg and append the corresponding checksum
func extendMsg(opts *LMOpts, C []byte, msg []byte, w, ls uint8) []byte {
	sh := hash.NewShakeHashEx()

	// extend hash as Q = H(I|q|D_MESG|C|msg)
	sh.Write(opts.I[:])
	sh.WriteUint32(opts.KeyIdx)
	sh.WriteUint16(D_MESG)
	sh.Write(C)
	sh.Write(msg)

	extMsg := make([]byte, len(C))
	sh.Read(extMsg)

	extMsg = append(extMsg, checksum(extMsg, w, ls)...)

	return extMsg
}

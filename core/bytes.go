package lmots

func coef(S []byte, i uint16, w uint8) uint8 {
	w16 := uint16(w)
	j := i * w16 / 8

	// number of bit to apply before masking
	bits := 8 - ((i % (8 / w16) * w16) + w16)

	return (((1 << w) - 1) & uint8(S[j]>>bits))
}

func checksum(msg []byte, w, ls uint8) uint16 {
	var sum uint16

	ell := uint16(len(msg) * 8)
	base := uint16((1 << w) - 1)
	for i := uint16(0); i < ell; i++ {
		sum += base - uint16(coef(msg, i, w))
	}

	return (sum << ls)
}

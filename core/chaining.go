package lmots

func evalChaining(I []byte, q uint32, j uint16,
	from uint8, to uint8, data []byte) []byte {

	out := make([]byte, len(data))
	copy(out, data)

	for j := from; j <= to; j++ {

	}

	return out
}

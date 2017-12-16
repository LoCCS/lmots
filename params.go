package lmots

// N is the security level measured in the bytes length
// of output of the hash function in use
const N = 32

// typecodes as prefix secret key, public key and signature
const (
	LMOTS_SHAKE256_N32_W2 = iota
	LMOTS_SHAKE256_N32_W4
)

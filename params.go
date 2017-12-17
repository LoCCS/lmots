package lmots

// N is the security level measured in the bytes length
// of output of the hash function in use
const N = 32

// typecodes as prefix secret key, public key and signature
// it takes form of "LMOTS_SHAKE{shake}_N{n}_W{w}"
// where shake is the version of the shake hash to use
// and n is the byte length of output fetching from the hash
// function every time
// w is the bit width of the Winternitz coefficient
const (
	LMOTS_SHAKE256_N32_W2 = iota
	LMOTS_SHAKE256_N32_W4
)

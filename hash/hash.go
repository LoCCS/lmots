package hash

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

func hashFunc() sha3.ShakeHash {
	return sha3.NewShake256()
}

// HashSubSk hash the given meta data to generate a component
// for some secret key
// @param[out] x		buffer to store the resultant component
// @param[in]  I		key pair identitifer, should be 22 bytes
// @param[in]  q		leaf index bound to this sk
// @param[in]  j		index of the private key component
// @param[in]  seed	nonce for randomization
func HashSubSk(x, I []byte, q uint32, j uint16, seed []byte) (int, error) {
	sha := hashFunc()

	// identifier
	sha.Write(I)

	buf := make([]byte, 4)
	// serialize and put q
	binary.BigEndian.PutUint32(buf, q)
	sha.Write(buf)

	// serialize and put j
	binary.BigEndian.PutUint16(buf[0:2], j)
	sha.Write(buf[0:2])

	// seed
	sha.Write(seed)

	return sha.Read(x)
}

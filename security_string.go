package lmots

import (
	"encoding/binary"
	"fmt"
)

// domain separation fields enumerators indicating the message to hash
// - D_PBLC = 0x8080 when computing the hash of all of the iterates
// 	in the LM-OTS algorithm
// - D_MESG = 0x8181 when computing the hash of the message in the
// 	LM-OTS algorithms
// - D_LEAF = 0x8282 when computing the hash of the leaf of an LMS
// 	tree
// - D_INTR = 0x8383 when computing the hash of an interior node of
// 	an LMS tree
const (
	D_PBLC = 0x8080
	D_MESG = 0x8181
	D_LEAF = 0x8282
	D_INTR = 0x8383
)

// SecurityString improves security against attacks that amortize their effort
// against multiple invocations of the hash function
// its layout goes as
// +----------------------------------------------------------------+
// | field	| range			| meaning																		|
// +----------------------------------------------------------------+
// | I			|  0-15			| key pair identifier												|
// +----------------------------------------------------------------+
// | r/q		| 16-19			| internal node index/leaf index						|
// +----------------------------------------------------------------+
// | D			| 20-21			| domain separation field										|
// +----------------------------------------------------------------+
// | j			|    22			| number of Winternitz iteration						|
// +----------------------------------------------------------------+
// | C			| 22-(21+n)	|	an n-byte randomizer for hashing message	|
// +----------------------------------------------------------------+
// where
// + range is in bytes
// + D is one of D_PBLC, D_MESG, D_LEAF, D_INTR, or i in [0,264],
//	assisting computing Winternitz chain or index of sk element
// + j is optional
// + C is optional
type SecurityString []byte

// offset
const (
	id_offset                 = 0
	rq_offset                 = id_offset + 16
	dsf_offset                = rq_offset + 4
	wtn_chain_num_iter_offset = dsf_offset + 2
	nonce_offset              = wtn_chain_num_iter_offset + 1
)

func newSecurityString() SecurityString {
	return make(SecurityString, 22)
}

func (ss SecurityString) setDSF(dsf uint16) {
	binary.BigEndian.PutUint16([]byte(ss)[dsf_offset:], dsf)
}
func (ss SecurityString) setID(I []byte) {
	copy([]byte(ss)[id_offset:rq_offset], I)
}
func (ss SecurityString) setNodeIdx(idx uint32) {
	binary.BigEndian.PutUint32([]byte(ss)[rq_offset:dsf_offset], idx)
}
func (ss SecurityString) setWtnChainNumItr(j byte) {
	rawss := []byte(ss)
	fmt.Println("hello")
	// expand rawss to make it long enough
	for len(rawss) <= wtn_chain_num_iter_offset {
		rawss = append(rawss, 0)
	}
	fmt.Println("hello2")
	rawss[wtn_chain_num_iter_offset] = j
	fmt.Println("hello3")

	// truncate rawss if necessary
	if len(rawss) > wtn_chain_num_iter_offset+1 {
		fmt.Println("hello31", len(rawss))
		rawss = rawss[:(wtn_chain_num_iter_offset + 1)]
		fmt.Println("hello32", len(rawss))
	}
	fmt.Println("hello4", len(rawss))

	ss = SecurityString(rawss)
}

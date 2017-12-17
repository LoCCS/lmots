package lmots

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

const (
	key_id_len = 16
)

type LMOpts struct {
	typecode [4]byte
	I        [key_id_len]byte
	keyIdx   uint32
}

func (opts *LMOpts) Clone() *LMOpts {
	optsC := *opts

	return &optsC
}

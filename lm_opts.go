package lmots

import "bytes"

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
	key_id_len = 16 // length of key pair identifier
)

// LMOpts wraps options for key generations, signing
// and verification
type LMOpts struct {
	// big-endian order bytes for LMOTS_SHAKE{shake}_N{n}_W{w}
	// typecodes defined in params.go
	Typecode [4]byte
	// key pair identifier
	I [key_id_len]byte
	// index of the current key pair
	KeyIdx uint32
}

// NewLMOpts makes an LM-OTS option with default `typecode`
// and `keyIdx` as 0
func NewLMOpts() *LMOpts {
	opts := new(LMOpts)

	opts.Typecode = METAOPTS_DEFAULT.typecode
	opts.KeyIdx = 0

	return opts
}

// Clone makes a copy of this *LMOpts
func (opts *LMOpts) Clone() *LMOpts {
	optsC := *opts

	return &optsC
}

// Equal checks the equality of two options
func (opts *LMOpts) Equal(rhs *LMOpts) bool {
	if opts == rhs {
		return true
	}
	return (nil != rhs) && bytes.Equal(opts.Typecode[:], rhs.Typecode[:]) &&
		bytes.Equal(opts.I[:], rhs.I[:]) && (opts.KeyIdx == rhs.KeyIdx)
}

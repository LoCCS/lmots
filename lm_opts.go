package lmots

import (
	"bytes"
	"encoding/binary"
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

const (
	key_id_len = 16 // length of key pair identifier
)

// LMOpts wraps options for key generations, signing
// and verification
type LMOpts struct {
	// big-endian order bytes for LMOTS_SHAKE{shake}_N{n}_W{w}
	// typecodes defined in params.go
	typecode [4]byte
	// key pair identifier
	I [key_id_len]byte
	// index of the current key pair
	keyIdx uint32
}

func NewLMOpts() *LMOpts {
	opts := new(LMOpts)

	opts.typecode = METAOPTS_DEFAULT.typecode
	opts.keyIdx = 0

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
	return (nil != rhs) && bytes.Equal(opts.typecode[:], rhs.typecode[:]) &&
		bytes.Equal(opts.I[:], rhs.I[:]) && (opts.keyIdx == rhs.keyIdx)
}

// KeyIdx returns the index assigned to this key
func (opts *LMOpts) KeyIdx() uint32 {
	return opts.keyIdx
}

// SetKeyIdx sets the index of underlying key
func (opts *LMOpts) SetKeyIdx(i uint32) {
	opts.keyIdx = i
}

// SetKeyID sets the identifier for the underlying key
func (opts *LMOpts) SetKeyID(I []byte) {
	if len(I) != key_id_len {
		panic("invalid key id length")
	}

	copy(opts.I[:], I)
}

func (opts *LMOpts) Serialize() []byte {
	buf := make([]byte, 1+4+1+key_id_len+1+4)
	offset := 0

	// len(typecode)|typecode
	buf[offset] = 4
	offset++
	copy(buf[offset:], opts.typecode[:])
	offset += 4

	// len(I)|I
	buf[offset] = uint8(key_id_len)
	offset++
	copy(buf[offset:], opts.I[:])
	offset += key_id_len

	// len(keyIdx)|keyIdx
	buf[offset] = 4
	offset++
	binary.BigEndian.PutUint32(buf[offset:], opts.keyIdx)

	return buf
}

func (opts *LMOpts) Deserialize(buf []byte) bool {
	var offset uint8 // := 0

	ell := buf[offset]
	offset += 1
	if 4 != ell {
		return false
		//panic("invalid length of typecode")
	}
	copy(opts.typecode[:], buf[offset:(offset+ell)])
	offset += ell

	ell = buf[offset]
	offset++
	if key_id_len != ell {
		//panic("invalid length of key identifier")
		return false
	}
	copy(opts.I[:], buf[offset:(offset+ell)])
	offset += ell

	ell = buf[offset]
	offset++
	opts.keyIdx = binary.BigEndian.Uint32(buf[offset:(offset + ell)])
	return true
}

// Type returns the typecode of this options
func (opts *LMOpts) Type() [4]byte {
	return opts.typecode
}

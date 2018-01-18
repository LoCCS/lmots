package hash

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// ShakeHashEx extends the sha3.ShakeHash,
// able to taking in uint32, uint16, uint8
type ShakeHashEx struct {
	sha3.ShakeHash
}

// NewShakeHashEx makes the ShakeHashEx
func NewShakeHashEx() *ShakeHashEx {
	return &ShakeHashEx{
		ShakeHash: sha3.NewShake256(),
	}
}

// WriteUint32 takes in an uint32 to update its
// internal state
func (sh *ShakeHashEx) WriteUint32(x uint32) {
	var buf [4]byte

	binary.BigEndian.PutUint32(buf[:], x)
	sh.Write(buf[:])
}

// WriteUint16 takes in an uint16 to update its
// internal state
func (sh *ShakeHashEx) WriteUint16(x uint16) {
	var buf [2]byte

	binary.BigEndian.PutUint16(buf[:], x)
	sh.Write(buf[:])
}

// WriteUint8 takes in an uint8 to update its
// internal state
func (sh *ShakeHashEx) WriteUint8(x uint8) {
	sh.Write([]byte{uint8(x)})
}

// Clone makes a copy of ShakeHashEx
func (sh *ShakeHashEx) Clone() *ShakeHashEx {
	return &ShakeHashEx{
		ShakeHash: sh.ShakeHash.Clone(),
	}
}

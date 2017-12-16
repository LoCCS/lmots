package hash

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

type ShakeHashEx struct {
	sha3.ShakeHash
}

func NewShakeHashEx() *ShakeHashEx {
	return &ShakeHashEx{
		ShakeHash: sha3.NewShake256(),
	}
}

//func (sh *ShakeHashEx) ReadUint32(x uint32) {
func (sh *ShakeHashEx) WriteUint32(x uint32) {
	var buf [4]byte

	binary.BigEndian.PutUint32(buf[:], x)
	sh.Write(buf[:])
}

func (sh *ShakeHashEx) WriteUint16(x uint16) {
	var buf [2]byte

	binary.BigEndian.PutUint16(buf[:], x)
	sh.Write(buf[:])
}

func (sh *ShakeHashEx) WriteUint8(x uint8) {
	sh.Write([]byte{uint8(x)})
}

func (sh *ShakeHashEx) Clone() *ShakeHashEx {
	return &ShakeHashEx{
		ShakeHash: sh.ShakeHash.Clone(),
	}
}

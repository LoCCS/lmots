package hash

import (
	"encoding/hex"
	"fmt"
)

func ExampleShakeHashEx() {
	I, _ := hex.DecodeString("8484aac063f6a062e5e7ccc0e6a377a0ef4a800a130c")
	var q uint32 = 2596996162
	var j uint16 = 222
	seed, _ := hex.DecodeString("7ec294f2d38a758be4b4c6353ebf7fc84abedf53f0f8ea3d89089e27c58e6a7c")

	x := make([]byte, 32)
	she := NewShakeHashEx()
	she.Write(I)
	she.WriteUint32(q)
	she.WriteUint16(j)
	she.Write(seed)

	she.Read(x)

	fmt.Printf("%x\n", x)
	// Output:
	// 0049c991ae106898d43a057971bbc7aed5fddfe881b798a2969e92aee7cc2b43
}

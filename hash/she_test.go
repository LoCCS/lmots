package hash

import (
	"bytes"
	"testing"
)

func TestShakeHashEx(t *testing.T) {
	she := NewShakeHashEx()
	she.Write([]byte("Hello World"))

	she2 := she.Clone()

	var x, y [32]byte

	she.Read(x[:])
	she2.Read(y[:])

	if !bytes.Equal(x[:], y[:]) {
		t.Fatalf("want %x, got %x", x[:], y[:])
	}
}

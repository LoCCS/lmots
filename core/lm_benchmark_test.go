package lmots

import (
	"testing"

	lmotsrand "github.com/LoCCS/lmots/rand"
)

func BenchmarkGenerateKey(b *testing.B) {
	dummyOpts := new(LMOpts)
	for i := 0; i < b.N; i++ {
		GenerateKey(dummyOpts, lmotsrand.Reader)
	}
}

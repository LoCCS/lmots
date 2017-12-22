package lmots

import (
	"testing"

	"github.com/LoCCS/lmots/rand"
)

func BenchmarkGenerateKey(b *testing.B) {
	dummyOpts := new(LMOpts)
	for i := 0; i < b.N; i++ {
		GenerateKey(dummyOpts, rand.Reader)
	}
}

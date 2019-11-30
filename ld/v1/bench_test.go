package v1

import (
	"golang.org/x/crypto/argon2"
	"testing"
)

func BenchmarkCostNormal(b *testing.B) {
	ch := defaultCryptoHeader()
	pass := []byte("testpassword")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(pass, ch.Salt(), ch.cp.Time(), ch.cp.Memory(), ch.cp.Threads(), uint32(96))
	}
}

func BenchmarkCostFast(b *testing.B) {
	ch := fastCryptoHeader()
	pass := []byte("testpassword")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(pass, ch.Salt(), ch.cp.Time(), ch.cp.Memory(), ch.cp.Threads(), uint32(96))
	}
}

func BenchmarkCostSlow(b *testing.B) {
	ch := slowCryptoHeader()
	pass := []byte("testpassword")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(pass, ch.Salt(), ch.cp.Time(), ch.cp.Memory(), ch.cp.Threads(), uint32(96))
	}
}

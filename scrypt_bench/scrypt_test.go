package scrypt_bench

import "testing"
import "code.google.com/p/go.crypto/scrypt"

var password = []byte("Password")
var salt = make([]byte, 16)

func BenchmarkR16384r8p1k32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
		if err != nil {
			b.Fatalf("%v", err)
		}
	}
}

func BenchmarkR16384r8p2k32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := scrypt.Key(password, salt, 16384, 8, 2, 32)
		if err != nil {
			b.Fatalf("%v", err)
		}
	}
}

func BenchmarkR16384r8p4k32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := scrypt.Key(password, salt, 16384, 8, 4, 32)
		if err != nil {
			b.Fatalf("%v", err)
		}
	}
}

func BenchmarkR32768r8p1k32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
		if err != nil {
			b.Fatalf("%v", err)
		}
	}
}

func BenchmarkR32768r8p2k32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := scrypt.Key(password, salt, 32768, 8, 2, 32)
		if err != nil {
			b.Fatalf("%v", err)
		}
	}
}

func BenchmarkR32768r8p4k32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := scrypt.Key(password, salt, 32768, 8, 4, 32)
		if err != nil {
			b.Fatalf("%v", err)
		}
	}
}

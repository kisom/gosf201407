package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"code.google.com/p/go.crypto/scrypt"
)

func Random(n int) ([]byte, error) {
	var bs = make([]byte, n)
	_, err := io.ReadFull(rand.Reader, bs)
	return bs, err
}

func main() {
	password := []byte("password")

	salt, err := Random(16)
	if err != nil {
		fmt.Printf("Failed to generate salt: %v\n", err)
		return
	}

	// Use password and salt with recommended default Scrypt
	// parameters to create a 32-byte NaCl secret key.
	key, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		fmt.Printf("Failed to generate key: %v\n", err)
		return
	}

	var naclKey [32]byte
	copy(naclKey[:], key)
	fmt.Printf("Secret key: %x\n", naclKey)
}

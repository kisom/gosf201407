package main

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"log"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
)

type Secret struct {
	Salt []byte
	Key  [32]byte
}

func Random(n int) ([]byte, error) {
	var bs = make([]byte, n)
	_, err := io.ReadFull(rand.Reader, bs)
	return bs, err
}

func NewSecret(password []byte) (secret *Secret, err error) {
	secret = new(Secret)

	secret.Salt, err = Random(16)
	if err != nil {
		return
	}

	key, err := scrypt.Key(password, secret.Salt, 16384, 8, 1, 32)
	if err != nil {
		return
	}

	copy(secret.Key[:], key)
	return
}

func updateNonce(nonce *[24]byte) {
	for i := 23; i >= 0; i-- {
		if nonce[i]++; nonce[i] != 0 {
			break
		}
	}
}

// This is a stub for the purposes of the demo.
func getNonce() [24]byte {
	var nonce [24]byte
	return nonce
}

func main() {
	password := []byte("password")
	secretKey, err := NewSecret(password) // Use Scrypt to hash password
	if err != nil {
		log.Fatal("%v", err)
	}

	// Get a valid nonce, never before used.
	var nonce = getNonce()

	message := []byte("Gophers of the world, unite!")
	encrypted := secretbox.Seal(nil, message, &nonce, &secretKey.Key)
	out := make([]byte, len(secretKey.Salt)+len(encrypted))

	// Encrypted message is prepended salt (for decryption) and ciphertext
	copy(out, secretKey.Salt)
	copy(out[len(secretKey.Salt):], encrypted)

	// Only use the nonce once with this key.
	updateNonce(&nonce)

	err = ioutil.WriteFile("secretmessage", out, 0644)
	if err != nil {
		log.Fatal("%v", err)
	}

	updateNonce(&nonce)
}

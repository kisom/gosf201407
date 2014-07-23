package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"code.google.com/p/go.crypto/nacl/box"
)

func updateNonce(nonce *[24]byte) {
	// stubbed
}

var nonce [24]byte

func main() {
	message := []byte("Gophers of the world, unite!")

	alicePublic, alicePrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate keypair for Alice: %v\n", err)
		return
	}

	bobPublic, bobPrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate keypair for Bob: %v\n", err)
		return
	}

	encrypted := box.Seal(nil, message, &nonce, bobPublic, alicePrivate)

	decrypted, ok := box.Open(nil, encrypted, &nonce, alicePublic, bobPrivate)
	if !ok {
		fmt.Println("Decryption failed.\n")
		return
	}

	if !bytes.Equal(message, decrypted) {
		fmt.Println("Message recovered failed.\n")
		return
	}

	// Nonce should only be used once.
	updateNonce(&nonce)

	fmt.Println("OK")
}

// FAIL-CLOSED TEST: a language your scanner may not support.
// Expected: either 2 findings (if Go is supported) or "could not analyze:
// unsupported language". It must NEVER report "quantum-safe" for this file.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

func main() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // FINDING 1: ECDSA P-256 key
	digest := sha256.Sum256([]byte("q-chain"))                 // DECOY: hash
	_, _, _ = ecdsa.Sign(rand.Reader, key, digest[:])         // FINDING 2: ECDSA sign
}

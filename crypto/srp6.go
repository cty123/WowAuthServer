package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
)

const N = "B79B3E2A87823CAB8F5EBFBF8EB10108535006298B5BADBD5B53E1895E644B89"

type Srp6 struct {
	b *big.Int
	v *big.Int
	g int
}

func GetN() ([]byte, error) {
	Nbyte, err := hex.DecodeString(N)
	if err != nil {
		return nil, err
	}

	return reverse(Nbyte), nil
}

func reverse(b []byte) []byte {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return b
}

func Nounce() ([]byte, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, errors.New("failed to generate random bytes")
	}

	return token, nil
}

func ComputerPublicB(verifier []byte) ([]byte, error) {
	// Read v as little endian
	v := big.NewInt(0).SetBytes(reverse(verifier))

	// Compute N as little endian
	Nbyte, err := hex.DecodeString(N)
	if err != nil {
		return nil, err
	}
	n := big.NewInt(0).SetBytes(reverse(Nbyte))

	// Generate random 32 bytes as b
	randBytes := [32]byte{}
	if _, err := rand.Read(randBytes[:]); err != nil {
		return nil, err
	}

	b := big.NewInt(0).SetBytes(randBytes[:])

	// Compute public B
	t0 := big.NewInt(0).Mul(big.NewInt(3), v)
	t0.Add(t0, big.NewInt(0).Exp(big.NewInt(7), b, n))
	B := t0.Mod(t0, n)

	return reverse(B.Bytes()), nil
}

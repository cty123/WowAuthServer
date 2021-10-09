package crypto

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"math/big"
)

const N = "B79B3E2A87823CAB8F5EBFBF8EB10108535006298B5BADBD5B53E1895E644B89"

func GetN() ([]byte, error) {
	n, err := hex.DecodeString(N)
	if err != nil {
		return nil, err
	}

	return reverse(n), nil
}

func GetRandomNounce() ([]byte, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, errors.New("failed to generate random bytes")
	}

	return token, nil
}

func ComputeEphemeralS(A big.Int, verifier big.Int, u big.Int, b big.Int) big.Int {
	Nbyte, _ := hex.DecodeString(N)
	N := big.NewInt(0).SetBytes(reverse(Nbyte))

	temp := A.Mul(&A, verifier.Exp(&verifier, &u, N))
	temp.Exp(temp, &b, N)

	return *temp
}

func ComputePublicB(verifier []byte) ([]byte, error) {
	// Read verifier as little endian
	v := big.NewInt(0).SetBytes(reverse(verifier))

	// Compute N as little endian
	Nbyte, err := hex.DecodeString(N)
	if err != nil {
		return nil, err
	}
	N := big.NewInt(0).SetBytes(reverse(Nbyte))

	// Generate random 32 bytes as b
	b := b()

	// Compute public B
	t0 := big.NewInt(0).Mul(big.NewInt(3), v)
	t0.Add(t0, big.NewInt(0).Exp(big.NewInt(7), b, N))
	B := t0.Mod(t0, N)

	return reverse(B.Bytes()), nil
}

func b() *big.Int {
	raw := "86C4C539C8BDA1F650CAB032199959D49E53E9539F4F9705B2C710B22448D96D"
	b, err := hex.DecodeString(raw)
	if err != nil {
		return big.NewInt(0)
	}
	return big.NewInt(0).SetBytes(reverse(b))
}

func u(A []byte, clientM []byte) *big.Int {
	h := sha1.New()
	h.Write(A)
	h.Write(clientM)
	res := h.Sum(nil)
	return big.NewInt(0).SetBytes(res)
}

func reverse(b []byte) []byte {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return b
}

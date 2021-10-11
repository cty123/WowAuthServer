package crypto

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"github.com/cty123/trinity-auth-server/infrastructure"
	"math/big"
)

func GetN() *big.Int {
	N := big.NewInt(0)
	bytes, err := hex.DecodeString("B79B3E2A87823CAB8F5EBFBF8EB10108535006298B5BADBD5B53E1895E644B89")
	if err == nil {
		N = N.SetBytes(infrastructure.Reverse(bytes))
	}

	return N
}

func GetRandomNounce() ([]byte, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, errors.New("failed to generate random bytes")
	}

	return token, nil
}

func ComputeEphemeralS(A *big.Int, verifier *big.Int, u *big.Int, b *big.Int) *big.Int {
	N := GetN()
	S := A.Mul(A, verifier.Exp(verifier, u, N))
	S = S.Exp(S, b, N)
	return S
}

func ComputeSessionKey(S *big.Int) *big.Int {
	bytes := S.Bytes()
	keyLen := len(bytes)
	bufLen := keyLen / 2

	// Interleave S into 2 pieces
	buf0 := make([]byte, bufLen)
	buf1 := make([]byte, bufLen)
	for i := 0; i < bufLen; i++ {
		buf0[i] = bytes[2*i+0]
		buf1[i] = bytes[2*i+1]
	}

	// Find first non-zero byte
	p := 0
	for p < keyLen && bytes[p] == 0 {
		p += 1
	}
	if p%2 == 0 {
		p++
	}
	p /= 2

	// Hash each of the halves, starting at the first nonzero byte
	h0 := sha1.New()
	h1 := sha1.New()
	h0.Write(buf0[p:])
	h1.Write(buf1[p:])
	hash0 := h0.Sum(nil)
	hash1 := h1.Sum(nil)

	// Stick back the 2 hashes
	hLen := len(hash0)
	kLen := 2 * hLen
	K := make([]byte, kLen)
	for i := 0; i < hLen; i++ {
		K[2*i+0] = hash0[i]
		K[2*i+1] = hash1[i]
	}

	return big.NewInt(0).SetBytes(K)
}

func ComputePublicB(verifier *big.Int, b *big.Int, N *big.Int) *big.Int {
	B := big.NewInt(0).Mul(big.NewInt(3), verifier)
	B.Add(B, big.NewInt(0).Exp(big.NewInt(7), b, N))
	B = B.Mod(B, N)
	return B
}

func ComputeSessionVerifier(A *big.Int, M1 []byte, K *big.Int) []byte {
	hash := sha1.New()
	hash.Write(A.Bytes())
	hash.Write(M1)
	hash.Write(K.Bytes())
	M2 := hash.Sum(nil)
	return M2
}

func GetRandomB() *big.Int {
	raw := "86C4C539C8BDA1F650CAB032199959D49E53E9539F4F9705B2C710B22448D96D"
	b, err := hex.DecodeString(raw)
	if err != nil {
		return big.NewInt(0)
	}
	return big.NewInt(0).SetBytes(infrastructure.Reverse(b))
}

func GetHashU(A *big.Int, B *big.Int) *big.Int {
	h := sha1.New()
	h.Write(A.Bytes())
	h.Write(B.Bytes())
	res := h.Sum(nil)
	return big.NewInt(0).SetBytes(res)
}

func GetVersionChallenge() []byte {
	return []byte{0xBA, 0xA3, 0x1E, 0x99, 0xA0, 0x0B, 0x21, 0x57, 0xFC, 0x37, 0x3F, 0xB3, 0x69, 0xCD, 0xD2, 0xF1}
}

func ComputeM1(N []byte, s []byte, A []byte, B []byte, K []byte) []byte {
	hash := sha1.New()
	hash.Write(N)
	nHash := hash.Sum(nil)

	hash.Reset()
	hash.Write([]byte{0x7})
	gHash := hash.Sum(nil)

	hLen := len(nHash)
	ngHash := make([]byte, hLen)
	for i := 0; i < hLen; i++ {
		ngHash[i] = nHash[i] ^ gHash[i]
	}

	hash.Reset()
	hash.Write([]byte("TEST"))
	hashU := hash.Sum(nil)

	hash.Reset()
	hash.Write(ngHash)
	hash.Write(hashU)
	hash.Write(s)
	hash.Write(A)
	hash.Write(B)
	hash.Write(K)
	return hash.Sum(nil)
}

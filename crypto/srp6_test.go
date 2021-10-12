package crypto

import (
	"encoding/hex"
	"github.com/cty123/trinity-auth-server/infrastructure"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strings"
	"testing"
)

func TestComputePublicB(t *testing.T) {
	v, err := hex.DecodeString("8DD50E4A81132CDA8D675687010C852CBBD23A1715724A35D7E5C38455D73F37")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	N := GetN()
	b := GetRandomB()
	B := ComputePublicB(big.NewInt(0).SetBytes(infrastructure.Reverse(v)), b, N)
	if err != nil {
		t.Logf("Incorrect public B returned by function ComputePublicB()")
		t.Fail()
	}

	expect := "7B0E4A098401AFF1050A15E9EF34534229E57C70B0DEC81F2CFBCBDC6671DA73"
	actual := strings.ToUpper(hex.EncodeToString(infrastructure.Reverse(B.Bytes())))

	assert.Equal(t, expect, actual, "The result should be equal")
}

func TestHashU(t *testing.T) {
	A, err := hex.DecodeString("EC895E045BB7DD628CCFA715116A39CB00C55B6361A229FA8DAC5B73D638773E")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	B, err := hex.DecodeString("7B0E4A098401AFF1050A15E9EF34534229E57C70B0DEC81F2CFBCBDC6671DA73")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	u := GetHashU(big.NewInt(0).SetBytes(infrastructure.Reverse(A)),
		big.NewInt(0).SetBytes(infrastructure.Reverse(B)))

	expect := "698F90382D1313D5FB888B34F8694BA95E4309E3"
	actual := strings.ToUpper(hex.EncodeToString(infrastructure.Reverse(u.Bytes())))

	assert.Equal(t, expect, actual, "The result should be equal")
}

//func TestComputeEphemeralS(t *testing.T) {
//	A, err := hex.DecodeString("EC895E045BB7DD628CCFA715116A39CB00C55B6361A229FA8DAC5B73D638773E")
//	if err != nil {
//		t.Logf("Failed to start the test, unable to decode the hex string")
//		t.Fail()
//	}
//
//	verifier, err := hex.DecodeString("8DD50E4A81132CDA8D675687010C852CBBD23A1715724A35D7E5C38455D73F37")
//	if err != nil {
//		t.Logf("Failed to start the test, unable to decode the hex string")
//		t.Fail()
//	}
//
//	u, err := hex.DecodeString("698F90382D1313D5FB888B34F8694BA95E4309E3")
//	if err != nil {
//		t.Logf("Failed to start the test, unable to decode the hex string")
//		t.Fail()
//	}
//
//	b, err := hex.DecodeString("86C4C539C8BDA1F650CAB032199959D49E53E9539F4F9705B2C710B22448D96D")
//	if err != nil {
//		t.Logf("Failed to start the test, unable to decode the hex string")
//		t.Fail()
//	}
//
//	S := ComputeEphemeralS(
//		big.NewInt(0).SetBytes(infrastructure.Reverse(A)),
//		big.NewInt(0).SetBytes(infrastructure.Reverse(verifier)),
//		big.NewInt(0).SetBytes(infrastructure.Reverse(u)),
//		big.NewInt(0).SetBytes(infrastructure.Reverse(b)))
//
//	expect := "4B9AA92FC209E663EF63E3D298661577927A741E7FCAD8E1D6F70CD655FAA645"
//	actual := strings.ToUpper(hex.EncodeToString(infrastructure.Reverse(S.Bytes())))
//
//	assert.Equal(t, expect, actual)
//}

func TestComputeSessionKey(t *testing.T) {
	S, err := hex.DecodeString("4B9AA92FC209E663EF63E3D298661577927A741E7FCAD8E1D6F70CD655FAA645")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	K := ComputeSessionKeyK(big.NewInt(0).SetBytes(infrastructure.Reverse(S)))

	expect := "3D41C92C4D1F32BADB7B2D413B6E67BC1A8C483CDE6FFD0D555F922B28617941D6B4E3942842E629"
	actual := strings.ToUpper(hex.EncodeToString(K))

	assert.Equal(t, expect, actual)
}

func TestComputeSessionVerifierM2(t *testing.T) {
	A, err := hex.DecodeString("EC895E045BB7DD628CCFA715116A39CB00C55B6361A229FA8DAC5B73D638773E")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	M1, err := hex.DecodeString("C80C301311D04379F0D00393DF0D478A6EEC2D00")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	K, err := hex.DecodeString("3D41C92C4D1F32BADB7B2D413B6E67BC1A8C483CDE6FFD0D555F922B28617941D6B4E3942842E629")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	M2 := GetSessionVerifierM2(big.NewInt(0).SetBytes(infrastructure.Reverse(A)), M1, K)

	expect := "1EEA742C32C30B49EA63161E91C38B5525C71CA7"
	actual := strings.ToUpper(hex.EncodeToString(M2))

	assert.Equal(t, expect, actual)
}

func TestComputeM1(t *testing.T) {
	NBytes, _ := hex.DecodeString("B79B3E2A87823CAB8F5EBFBF8EB10108535006298B5BADBD5B53E1895E644B89")
	N := big.NewInt(0).SetBytes(infrastructure.Reverse(NBytes))

	saltBytes, _ := hex.DecodeString("8598916D316FF8153C23AE77CE67009C683FD10DF8F66F6E96050C870208DB16")

	ABytes, _ := hex.DecodeString("EC895E045BB7DD628CCFA715116A39CB00C55B6361A229FA8DAC5B73D638773E")
	A := big.NewInt(0).SetBytes(infrastructure.Reverse(ABytes))

	BBytes, _ := hex.DecodeString("7B0E4A098401AFF1050A15E9EF34534229E57C70B0DEC81F2CFBCBDC6671DA73")
	B := big.NewInt(0).SetBytes(infrastructure.Reverse(BBytes))

	K, _ := hex.DecodeString("3D41C92C4D1F32BADB7B2D413B6E67BC1A8C483CDE6FFD0D555F922B28617941D6B4E3942842E629")

	expect := "C80C301311D04379F0D00393DF0D478A6EEC2D00"
	actual := strings.ToUpper(hex.EncodeToString(ComputeM1(N, "TEST", infrastructure.Reverse(saltBytes), A, B, K)))

	assert.Equal(t, expect, actual)
}

package crypto

import (
	"encoding/hex"
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

	publicB, err := ComputePublicB(v)
	if err != nil {
		t.Logf("Incorrect public B returned by function ComputePublicB()")
		t.Fail()
	}

	exp := "7B0E4A098401AFF1050A15E9EF34534229E57C70B0DEC81F2CFBCBDC6671DA73"
	B := strings.ToUpper(hex.EncodeToString(publicB))

	assert.Equal(t, exp, B, "The result should be equal")
}

func TestU(t *testing.T) {
	A, err := hex.DecodeString("EC895E045BB7DD628CCFA715116A39CB00C55B6361A229FA8DAC5B73D638773E")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	clientM, err := hex.DecodeString("7B0E4A098401AFF1050A15E9EF34534229E57C70B0DEC81F2CFBCBDC6671DA73")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	exp, err := hex.DecodeString("698F90382D1313D5FB888B34F8694BA95E4309E3")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	u := u(A, clientM)
	assert.Equal(t, u, big.NewInt(0).SetBytes(exp))
}

func TestComputeEphemeralS(t *testing.T) {
	A, err := hex.DecodeString("EC895E045BB7DD628CCFA715116A39CB00C55B6361A229FA8DAC5B73D638773E")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	verifier, err := hex.DecodeString("8DD50E4A81132CDA8D675687010C852CBBD23A1715724A35D7E5C38455D73F37")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	u, err := hex.DecodeString("698F90382D1313D5FB888B34F8694BA95E4309E3")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	b, err := hex.DecodeString("86C4C539C8BDA1F650CAB032199959D49E53E9539F4F9705B2C710B22448D96D")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	exp, err := hex.DecodeString("4B9AA92FC209E663EF63E3D298661577927A741E7FCAD8E1D6F70CD655FAA645")
	if err != nil {
		t.Logf("Failed to start the test, unable to decode the hex string")
		t.Fail()
	}

	S := ComputeEphemeralS(*big.NewInt(0).SetBytes(reverse(A)), *big.NewInt(0).SetBytes(reverse(verifier)),
		*big.NewInt(0).SetBytes(reverse(u)), *big.NewInt(0).SetBytes(reverse(b)))

	assert.Equal(t, S, *big.NewInt(0).SetBytes(reverse(exp)))
}

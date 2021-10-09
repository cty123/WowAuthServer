package handler

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSha1(t *testing.T) {
	h := sha1.New()

	A, _ := hex.DecodeString("EC895E045BB7DD628CCFA715116A39CB00C55B6361A229FA8DAC5B73D638773E")
	clientM, _ := hex.DecodeString("7B0E4A098401AFF1050A15E9EF34534229E57C70B0DEC81F2CFBCBDC6671DA73")

	h.Write(A)
	h.Write(clientM)
	res := h.Sum(nil)

	fmt.Println(res)
}

package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSrp6(t *testing.T) {
	v, err := hex.DecodeString("8DD50E4A81132CDA8D675687010C852CBBD23A1715724A35D7E5C38455D73F37")
	if err != nil {
		return
	}

	bytes, _ := ComputerPublicB(v)
	fmt.Println("N bytes", bytes)
}

package infrastructure

import (
	"fmt"
	"reflect"
	"testing"
)

type AuthLogonPacket struct {
	Command         uint8
	Error           byte
	Size            [2]byte
	GameName        [4]byte
	Version         [3]byte
	Build           [2]byte
	Platform        [4]byte
	Os              [4]byte
	Country         [4]byte
	TimezoneBias    [4]byte
	Ip              [4]byte
	ChallengeLength byte
	Challenge       *[]byte
}

type TestSlice struct {
	S []byte
}

func TestSerializer(t *testing.T) {
	// a := AuthLogonPacket{}
	// Deserialize(a)
	b := []byte{1, 2, 3, 4}
	ts := TestSlice{
		b,
	}
	value := reflect.ValueOf(&ts).Elem()
	field := value.Field(0)
	fmt.Println(field.Len(), field.Kind())
}

package protocol

type RealmListRequest struct {
	Command     byte
	Placeholder [4]byte
}

type RealmListResponseHeader struct {
	Command  byte
	Size     uint16
	Padding  uint32
	RealmNum uint16
}

type RealmListResponseBody struct {
	RealmType     uint8
	Locked        uint8
	RealmFlags    byte
	RealmName     []byte
	AddressPort   []byte
	Population    uint32
	NumCharacter  uint8
	RealmCategory uint8
	RealmId       uint8
}

type RealmListResponseFooter struct {
	Padding uint16
}

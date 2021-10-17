package protocol

type AuthLogonRequest struct {
	Command         byte
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
}

type AuthLogonResponse struct {
	Command         byte
	Unknown1        byte
	Status          byte
	B               [32]byte
	GeneratorLength byte
	Generator       byte
	NLength         byte
	N               [32]byte
	Salt            [32]byte
	Random          [16]byte
	SecurityFlags   byte
}

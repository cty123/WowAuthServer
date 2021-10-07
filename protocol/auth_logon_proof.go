package protocol

type AuthLogonProofRequest struct {
	Command       byte
	A             [32]byte
	ClientM       [20]byte
	CRC           [20]byte
	KeyNumber     byte
	SecurityFlags byte
}

package protocol

type AuthLogonProofRequest struct {
	Command       byte
	A             [32]byte
	ClientM       [20]byte
	CRC           [20]byte
	KeyNumber     byte
	SecurityFlags byte
}

type AuthLogonProofResponse struct {
	Command      byte
	Error        byte
	M2           [20]byte
	AccountFlags uint32
	SurveyId     uint32
	LoginFlags   uint16
}

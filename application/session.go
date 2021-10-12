package application

import (
	"github.com/cty123/trinity-auth-server/infrastructure"
	"github.com/cty123/trinity-auth-server/protocol"
	log "github.com/sirupsen/logrus"
	"math/big"
)

type Session struct {
	Conn        *infrastructure.Connection
	Salt        []byte
	Verifier    *big.Int
	N           *big.Int
	B           *big.Int
	AccountName string
}

func NewSession(conn *infrastructure.Connection) *Session {
	return &Session{
		conn,
		nil,
		nil,
		nil,
		nil,
		"",
	}
}

func (session *Session) ReadCommand() (byte, error) {
	return session.Conn.PeekByte()
}

func (session *Session) SetVerifier(verifier *big.Int) {
	session.Verifier = verifier
}

func (session *Session) SetN(N *big.Int) {
	session.N = N
}

func (session *Session) SetB(B *big.Int) {
	session.B = B
}

func (session *Session) SetAccountName(accountName string) {
	session.AccountName = accountName
}

func (session *Session) SetSalt(salt []byte) {
	session.Salt = salt
}

// Read and write AuthLogonRequest - AuthLogonResponse

func (session *Session) ReadAuthLogonRequest() (*protocol.AuthLogonRequest, string, error) {
	packet := protocol.AuthLogonRequest{}
	if err := infrastructure.Deserialize(session.Conn, &packet); err != nil {
		log.Info("Error encountered while reading AuthLogonRequest: ", err)
		return nil, "", err
	}

	accountBuffer := make([]byte, packet.ChallengeLength)
	if _, err := session.Conn.Read(accountBuffer); err != nil {
		log.Info("Error encountered while reading account name: ", err)
		return nil, "", err
	}

	return &packet, string(accountBuffer), nil
}

func (session *Session) WriteAuthLogonResponse(response *protocol.AuthLogonResponse) error {
	return infrastructure.Serialize(session.Conn, response)
}

// Read and write AuthLogonProofRequest/AuthLogonProofResponse

func (session *Session) ReadAuthLogonProofRequest() (*protocol.AuthLogonProofRequest, error) {
	request := protocol.AuthLogonProofRequest{}
	if err := infrastructure.Deserialize(session.Conn, &request); err != nil {
		log.Info("Error encountered while reading AuthLogonProofRequest: ", err)
		return nil, err
	}

	return &request, nil
}

func (session *Session) WriteAuthLogonProofResponse(response *protocol.AuthLogonProofResponse) error {
	return infrastructure.Serialize(session.Conn, response)
}

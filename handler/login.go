package handler

import (
	"github.com/cty123/trinity-auth-server/application"
	"github.com/cty123/trinity-auth-server/crypto"
	"github.com/cty123/trinity-auth-server/infrastructure"
	"github.com/cty123/trinity-auth-server/protocol"
	"github.com/cty123/trinity-auth-server/service"
	log "github.com/sirupsen/logrus"
	"math/big"
)

type LoginHandler struct {
	handlerMap     map[uint8]func(session *application.Session) error
	accountService *service.AccountService
}

func NewLoginHandler(accountService *service.AccountService) LoginHandler {
	handlerMap := make(map[uint8]func(session *application.Session) error)
	handler := LoginHandler{
		handlerMap,
		accountService,
	}
	handler.initialize()
	return handler
}

func (handler *LoginHandler) initialize() {
	handler.handlerMap[0] = handler.HandleAuthLogon
	handler.handlerMap[1] = handler.HandleAuthLogonProof
}

func (handler *LoginHandler) Handle(conn infrastructure.Connection) error {
	defer conn.Close()

	session := application.NewSession(&conn)

	for {
		// Read command byte
		cmd, err := session.ReadCommand()
		if err != nil {
			return err
		}

		log.Info("Received client command ", cmd)

		// Get handler from map and invoke handler
		handlerFunc := handler.handlerMap[cmd]
		if err := handlerFunc(session); err != nil {
			return err
		}
	}
}

func (handler *LoginHandler) HandleAuthLogon(session *application.Session) error {
	// Read the packet from connection
	_, accountName, err := session.ReadAuthLogonRequest()
	if err != nil {
		return err
	}

	// Retrieve the account from database
	account := handler.accountService.FindAccountByAccountName(accountName)

	session.SetVerifier(account.Verifier)

	N := crypto.GetN()
	b := crypto.GetRandomB()
	B := crypto.ComputePublicB(session.Verifier, b, N)

	session.SetB(B)

	response := protocol.AuthLogonResponse{
		B:               infrastructure.Reverse(B.Bytes()),
		GeneratorLength: 1,
		Generator:       7,
		NLength:         32,
		N:               infrastructure.Reverse(N.Bytes()),
		Salt:            account.Salt,
		Random:          crypto.GetVersionChallenge(),
	}

	if err := session.WriteAuthLogonResponse(&response); err != nil {
		return err
	}

	return nil
}

func (handler *LoginHandler) HandleAuthLogonProof(session *application.Session) error {
	request, err := session.ReadAuthLogonProofRequest()
	if err != nil {
		return err
	}

	A := big.NewInt(0).SetBytes(infrastructure.Reverse(request.A[:]))

	log.Info("Received ClientM ", request.ClientM)
	log.Info("Received A ", request.A)

	u := crypto.GetHashU(A, session.B)
	b := crypto.GetRandomB()
	S := crypto.ComputeEphemeralS(A, session.Verifier, u, b)
	K := crypto.ComputeSessionKey(S)
	M2 := crypto.ComputeSessionVerifier(A, request.ClientM[:], K)

	response := protocol.AuthLogonProofResponse{
		Command:      1,
		Error:        0,
		M2:           M2,
		AccountFlags: []byte{0x0, 0x80, 0x0, 0x0},
		SurveyId:     []byte{0x0, 0x0, 0x0, 0x0},
		LoginFlags:   []byte{0x0, 0x0},
	}

	if err := session.WriteAuthLogonProofResponse(&response); err != nil {
		return err
	}

	return nil
}

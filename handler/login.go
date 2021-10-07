package handler

import (
	"github.com/cty123/trinity-auth-server/crypto"
	"github.com/cty123/trinity-auth-server/infrastructure"
	"github.com/cty123/trinity-auth-server/protocol"
	"github.com/cty123/trinity-auth-server/service"
	log "github.com/sirupsen/logrus"
)

type LoginHandler struct {
	handlerMap     map[uint8]func(infrastructure.Connection) error
	accountService *service.AccountService
}

func NewLoginHandler(accountService *service.AccountService) LoginHandler {
	handlerMap := make(map[uint8]func(infrastructure.Connection) error)
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

	for {
		// Read command byte
		cmd, err := conn.PeekByte()
		if err != nil {
			return err
		}

		log.Info("Received client command ", cmd)

		// Get handler from map and invoke handler
		handlerFunc := handler.handlerMap[cmd]
		if err := handlerFunc(conn); err != nil {
			return err
		}
	}
}

func (handler *LoginHandler) HandleAuthLogon(conn infrastructure.Connection) error {
	// Read the packet from connection
	packet := protocol.AuthLogonRequest{}
	if err := infrastructure.Deserialize(conn, &packet); err != nil {
		log.Info("Error encountered while reading AuthLogon packet: ", err)
		return err
	}

	// Read account name based on the packet header
	accountBuffer := make([]byte, packet.ChallengeLength)
	if _, err := conn.Read(accountBuffer); err != nil {
		return err
	}

	accountName := string(accountBuffer)
	account := handler.accountService.FindAccountByAccountName(accountName)

	// Compute srp6 public key
	salt := account.Salt
	verifier := account.Verifier

	B, err := crypto.ComputerPublicB(verifier)
	if err != nil {
		return err
	}

	random, err := crypto.Nounce()
	if err != nil {
		return err
	}

	N, err := crypto.GetN()
	if err != nil {
		return err
	}

	response := protocol.AuthLogonResponse{
		B:               B,
		GeneratorLength: 1,
		Generator:       7,
		NLength:         32,
		N:               N,
		Salt:            salt,
		Random:          random,
	}

	if err := infrastructure.Serialize(conn, &response); err != nil {
		return err
	}

	return nil
}

func (handler *LoginHandler) HandleAuthLogonProof(conn infrastructure.Connection) error {
	// Read the packet from connection
	packet := protocol.AuthLogonProofRequest{}
	if err := infrastructure.Deserialize(conn, &packet); err != nil {
		log.Info("Error encountered while reading AuthLogonProof packet: ", err)
		return err
	}

	// Don't check anything and just return success
	conn.WriteByte(1)
	conn.WriteByte(0)
	//conn.WriteByte([]{})
	//conn.Write()

	return nil
}

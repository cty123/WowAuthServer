package handler

import (
	"encoding/hex"
	"fmt"
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
	handler.handlerMap[16] = handler.HandleRealmList
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

	N := crypto.GetN()
	b := crypto.GetRandomB()
	v := big.NewInt(0).SetBytes(infrastructure.Reverse(account.Verifier[:]))
	B := crypto.ComputePublicB(v, b, N)

	session.SetSessionSecrets(v, N, B, accountName, account.Salt)

	response := protocol.AuthLogonResponse{
		GeneratorLength: 1,
		Generator:       7,
		NLength:         32,
	}
	copy(response.B[:], infrastructure.Reverse(B.Bytes()))
	copy(response.N[:], infrastructure.Reverse(N.Bytes()))
	copy(response.Salt[:], account.Salt)
	copy(response.Random[:], crypto.GetVersionChallenge())

	log.Info("Sending N ", hex.EncodeToString(infrastructure.Reverse(N.Bytes())))

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

	// A is passed in little endian and therefore needs to be reversed
	A := big.NewInt(0).SetBytes(infrastructure.Reverse(request.A[:]))
	B := session.B

	log.Info("Received A ", request.A)

	u := crypto.GetHashU(A, B)
	b := crypto.GetRandomB()
	S := crypto.ComputeEphemeralS(A, session.Verifier, u, b)
	K := crypto.ComputeSessionKeyK(S)

	serverM := crypto.ComputeM1(session.N, session.AccountName, session.Salt, A, B, K)

	log.Infof("Computed M1: %s, client M1: %s", hex.EncodeToString(serverM), hex.EncodeToString(request.ClientM[:]))

	M2 := crypto.GetSessionVerifierM2(A, request.ClientM[:], K)

	handler.accountService.SaveAccountInfo(session.AccountName, K)

	response := protocol.AuthLogonProofResponse{
		Command:      1,
		Error:        0,
		AccountFlags: 0x00800000,
		SurveyId:     0,
		LoginFlags:   0,
	}
	copy(response.M2[:], M2)

	if err := session.WriteAuthLogonProofResponse(&response); err != nil {
		return err
	}

	return nil
}

func (handler *LoginHandler) HandleRealmList(session *application.Session) error {
	if _, err := session.ReadRealmListRequest(); err != nil {
		return err
	}

	realmList := handler.accountService.FindAllRealms()

	responseHeader := protocol.RealmListResponseHeader{
		Command:  16,
		Size:     0,
		Padding:  0,
		RealmNum: uint16(len(realmList)),
	}

	realms := make([]protocol.RealmListResponseBody, len(realmList))
	for i, realm := range realmList {
		realms[i] = protocol.RealmListResponseBody{
			RealmType:     realm.Icon,
			Locked:        0,
			RealmFlags:    realm.Flag,
			RealmName:     append([]byte(realm.Name), []byte{0}...),
			AddressPort:   append([]byte(fmt.Sprintf("%s:%d", realmList[i].Address, realmList[i].Port)), []byte{0}...),
			Population:    realmList[i].Population,
			NumCharacter:  0,
			RealmCategory: realmList[i].Timezone,
			RealmId:       realmList[i].Id,
		}
	}

	responseFooter := protocol.RealmListResponseFooter{
		Padding: 0x1000,
	}

	if err := session.WriteRealmListResponse(responseHeader, realms, responseFooter); err != nil {
		log.Errorf("Failed to write response: %s", err)
		return err
	}

	return nil
}

package service

import (
	"github.com/cty123/trinity-auth-server/entity"
	"gorm.io/gorm"
)

type AccountService struct {
	db *gorm.DB
}

func NewAccountService(db *gorm.DB) *AccountService {
	return &AccountService{
		db,
	}
}

func (accountService *AccountService) FindAccountByAccountName(accountName string) entity.Account {
	var account entity.Account
	accountService.db.First(&account, 2)
	return account
}

func (accountService *AccountService) FindAllRealms() []entity.Realm {
	var realm []entity.Realm
	accountService.db.Find(&realm)
	return realm
}

func (accountService *AccountService) SaveAccountInfo(username string, sessionKey []byte) {
	accountService.db.Model(&entity.Account{}).Where("username", username).Update("session_key_auth", sessionKey)
}

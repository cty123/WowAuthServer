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

package service

import (
	"github.com/cty123/trinity-auth-server/entity"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"testing"
)

func TestRealmList(t *testing.T) {
	db, _ := gorm.Open(mysql.New(mysql.Config{
		DSN:                       "root:19971112@tcp(127.0.0.1:3306)/auth?charset=utf8&parseTime=True&loc=Local",
		DefaultStringSize:         256,
		DisableDatetimePrecision:  true,
		DontSupportRenameIndex:    true,
		DontSupportRenameColumn:   true,
		SkipInitializeWithVersion: false,
	}), &gorm.Config{})

	var realm []entity.Realm
	db.Find(&realm)

	t.Log(realm)
}

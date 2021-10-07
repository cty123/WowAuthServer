package entity

import "time"

type Account struct {
	Id             int `gorm:"primaryKey"`
	Username       string
	Salt           []uint8
	Verifier       [32]uint8
	SessionKeyAuth []uint8
	SessionKeyBnet []uint8
	TotpSecret     []uint8
	Email          string
	RegEmail       string
	JoinDate       time.Time
	LastIp         string
	LastAttemptIp  string
	FailedLogins   int
	Locked         bool
	LockedCountry  string
	LastLogin      time.Time
	Online         int
	Expansion      int
	Local          int
	Os             string
	Recruiter      int
}

func (Account) TableName() string {
	return "account"
}

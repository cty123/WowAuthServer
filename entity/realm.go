package entity

type Realm struct {
	Id                   uint8  `gorm:"primaryKey"`
	Name                 string `gorm:"unique"`
	Address              string
	LocalAddress         string `gorm:"column:localAddress"`
	LocalSubnetMask      string `gorm:"column:localSubnetMask"`
	Port                 uint16
	Icon                 uint8
	Flag                 uint8
	Timezone             uint8
	AllowedSecurityLevel uint8 `gorm:"allowedSecurityLevel"`
	Population           uint32
	Gamebuild            uint32
}

func (Realm) TableName() string {
	return "realmlist"
}

package entity

type Realm struct {
	Id                   int32  `gorm:"primaryKey"`
	Name                 string `gorm:"unique"`
	Address              string
	LocalAddress         string
	LocalSubnetMask      string
	Port                 int16
	Icon                 int8
	Flag                 int8
	Timezone             int8
	AllowedSecurityLevel int8
	Population           int32
	Gamebuild            int32
}

func (Realm) TableName() string {
	return "realmlist"
}

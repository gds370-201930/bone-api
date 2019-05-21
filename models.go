package main

// User represents a user in the database
type User struct {
	Email          string `gorm:"column:email;unique"`
	Password       string `gorm:"column:passWord"`
	Username       string `gorm:"column:userName;unique"`
	Model          int32  `gorm:"column:model"`
	Wins           int32  `gorm:"column:wins"`
	Losses         int32  `gorm:"column:losses"`
	MostPlayedGame string `gorm:"column:mostPlydGame"`
	Kills          int32  `gorm:"column:kills"`
	Deaths         int32  `gorm:"column:deaths"`
	KD             int32  `gorm:"column:kdRatio"`
}

func (User) TableName() string {
	return "userData"
}

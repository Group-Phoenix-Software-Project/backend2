package types

import (
	"time"

	"gorm.io/gorm"
)

type Customer struct {
	gorm.Model
	Id          int        `gorm:"primary, autoIncrement" json:"id"`
	FirstName   string     `json:"firstName"`
	LastName    string     `json:"lastName"`
	Email       string     `gorm:"unique" json:"email" validate:"email,required"`
	Password    string     `json:"password"`
	Designation string     `json:"designation"`
	Address     string     `json:"address"`
	DOB         *time.Time `json:"dob"`
}

type PasswordReset struct {
	gorm.Model
	Id    uint
	Email string
	Token string `gorm:"unique"`
}

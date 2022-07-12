package types

import (
	"time"

	"gorm.io/gorm"
)

type Employee struct {
	gorm.Model
	Id          int        `gorm:"primary, autoIncrement" json:"id"`
	FirstName   string     `json:"firstName"`
	LastName    string     `json:"lastName"`
	Designation string     `json:"designation"`
	Address     string     `json:"address"`
	Email       string     `json:"email"`
	Password    string     `json:"password"`
	DOB         *time.Time `json:"dob"`
	Salary      float32    `json:"salary"`
	Position    string     `json:"position"`
}

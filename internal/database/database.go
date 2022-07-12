package database

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func NewDatabase() (*gorm.DB, error) {
	logrus.Info("Setting up Connection with the Database")

	dbUsername := "root"
	dbPassword := "root"

	dsn := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/shopdb?charset=utf8mb4&parseTime=True&loc=Local", dbUsername, dbPassword)
	logrus.Info(dsn)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})

	if err != nil {
		return db, err
	}

	DB = db
	return db, nil
}

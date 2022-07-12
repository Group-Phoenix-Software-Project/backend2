package catogary

import "gorm.io/gorm"

type Service struct {
	DB *gorm.DB
}

// create a instance of service
func NewService(db *gorm.DB) *Service {
	return &Service{
		DB: db,
	}
}

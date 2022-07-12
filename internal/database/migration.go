package database

import (
	"backend/internal/types"

	"gorm.io/gorm"
)

func MigrateDB(db *gorm.DB) error {
	if err := db.AutoMigrate(&types.Catogary{}, &types.Item{}, &types.Purcahse{}, &types.Customer{}, &types.Employee{}); err != nil {
		return err
	}
	return nil
}

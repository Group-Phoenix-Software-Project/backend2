package types

type Catogary struct {
	Model
	Title       string `json:"title"`
	Description string `json:"description"`
	Products    []Item `gorm:"foreignKey:ID"`
}

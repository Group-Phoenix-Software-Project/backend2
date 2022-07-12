package catogary

import "backend/internal/types"

func (s *Service) GetCatogaryWithProducts() []types.Catogary {
	var catogarys []types.Catogary

	s.DB.Debug().Preload("Products").Find(&catogarys)
	return catogarys
}

func (s *Service) CreateCatogary(item types.Catogary) (types.Catogary, error) {
	if result := s.DB.Save(&item); result.Error != nil {
		return types.Catogary{}, result.Error
	}
	return item, nil
}

func (s *Service) AddProduct(catogary types.Catogary, product types.Item) types.Catogary {
	catogary.Products = append(catogary.Products, product)
	s.DB.Save(&catogary)
	return catogary
}

func (s *Service) GetCatogaryBySlug(slug string) types.Catogary {
	var catogarys types.Catogary

	s.DB.Debug().Preload("Products").Find(&catogarys).Where("title = ?", slug)
	return catogarys
}

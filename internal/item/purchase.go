package item

import "backend/internal/types"

func (s *Service) SavePurchase(purcahse types.Purcahse) (types.Purcahse, error) {
	if result := s.DB.Save(&purcahse); result.Error != nil {
		return types.Purcahse{}, result.Error
	}
	return purcahse, nil
}

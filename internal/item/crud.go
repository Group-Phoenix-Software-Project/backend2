package item

import "backend/internal/types"

func (s *Service) SaveItem(item types.Item) (types.Item, error) {
	if result := s.DB.Save(&item); result.Error != nil {
		return types.Item{}, result.Error
	}
	return item, nil
}

func (s *Service) GetPosts() []types.Item {
	var items []types.Item
	s.DB.Debug().Find(&items)
	return items
}

func (s *Service) GetItemByID(id uint64) types.Item {
	var item types.Item
	s.DB.Debug().Where("id = ?", id).First(&item)
	return item
}

func (s *Service) DeleteItem(id uint64) {
	s.DB.Debug().Delete(&types.Item{}, id)
}

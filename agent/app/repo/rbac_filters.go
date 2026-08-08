package repo

import "gorm.io/gorm"

// WithByNames constrains repository queries before count/pagination. An empty
// list deliberately returns no rows instead of omitting the filter.
func WithByNames(names []string) DBOption {
	return func(g *gorm.DB) *gorm.DB {
		if len(names) == 0 {
			return g.Where("1 = 0")
		}
		return g.Where("name IN (?)", names)
	}
}

func WithByIDsOrNames(ids []uint, names []string) DBOption {
	return func(g *gorm.DB) *gorm.DB {
		switch {
		case len(ids) == 0 && len(names) == 0:
			return g.Where("1 = 0")
		case len(ids) == 0:
			return g.Where("name IN (?)", names)
		case len(names) == 0:
			return g.Where("id IN (?)", ids)
		default:
			return g.Where("id IN (?) OR name IN (?)", ids, names)
		}
	}
}

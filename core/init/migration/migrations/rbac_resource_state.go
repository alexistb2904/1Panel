package migrations

import (
	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// AddCommunityRBACResourceState separates a creation reservation from an active
// authorization grant. Existing ownership rows are active; new creations may
// use a short-lived pending row until the Agent has actually completed them.
var AddCommunityRBACResourceState = &gormigrate.Migration{
	ID: "20260808-add-community-rbac-resource-state",
	Migrate: func(tx *gorm.DB) error {
		if err := tx.AutoMigrate(&model.AccessProjectResource{}); err != nil {
			return err
		}
		return tx.Model(&model.AccessProjectResource{}).
			Where("state = ? OR state IS NULL", "").
			Update("state", model.AccessResourceStateActive).Error
	},
}

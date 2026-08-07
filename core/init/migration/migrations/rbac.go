package migrations

import (
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// AddCommunityRBAC introduces the open-source multi-user authorization schema.
// It intentionally runs after InitSetting so existing single-admin Community
// installations can bootstrap their current administrator into rbac_users.
var AddCommunityRBAC = &gormigrate.Migration{
	ID: "20260807-add-community-rbac",
	Migrate: func(tx *gorm.DB) error {
		return rbac.MigrateAndSeed(tx)
	},
}

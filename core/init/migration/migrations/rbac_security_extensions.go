package migrations

import (
	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

var AddCommunityRBACSecurityExtensions = &gormigrate.Migration{
	ID: "20260807-add-community-rbac-security-extensions",
	Migrate: func(tx *gorm.DB) error {
		return tx.AutoMigrate(
			&model.AccessNodeScope{},
			&model.AccessServiceCredential{},
			&model.AccessAuditEvent{},
		)
	},
}

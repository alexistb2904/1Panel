package migrations

import (
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// HardenCommunityRBACDefaultRolesV2 is intentionally a new migration ID. The
// first hardening migration may already have executed on installations that
// followed this branch while security review continued; subsequent removal of
// async Runtime/Compose lifecycle grants and raw Compose environment access must
// therefore be re-applied deterministically to those existing databases.
var HardenCommunityRBACDefaultRolesV2 = &gormigrate.Migration{
	ID: "20260808-harden-community-rbac-default-roles-v2",
	Migrate: func(tx *gorm.DB) error {
		return rbac.MigrateAndSeed(tx)
	},
}

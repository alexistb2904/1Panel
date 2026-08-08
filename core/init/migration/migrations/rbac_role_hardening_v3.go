package migrations

import (
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// HardenCommunityRBACDefaultRolesV3 removes scoped raw-filesystem capabilities
// after the adversarial review established that pathname validation cannot be
// an atomic hostile-tenant boundary. This is a new migration ID because v1/v2
// may already be recorded on installations following the development branch.
var HardenCommunityRBACDefaultRolesV3 = &gormigrate.Migration{
	ID: "20260808-harden-community-rbac-default-roles-v3",
	Migrate: func(tx *gorm.DB) error {
		return rbac.MigrateAndSeed(tx)
	},
}

package migrations

import (
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// HardenCommunityRBACDefaultRoles reapplies the deterministic built-in role
// policy after security hardening. Existing installations may already have run
// the initial RBAC seed, so changing DefaultRoleDefinitions in code alone would
// leave stale dangerous grants in rbac_role_permissions. MigrateAndSeed is
// intentionally idempotent for built-in permissions/roles and preserves users,
// projects and bindings while replacing only each system role's permission set.
var HardenCommunityRBACDefaultRoles = &gormigrate.Migration{
	ID: "20260808-harden-community-rbac-default-roles",
	Migrate: func(tx *gorm.DB) error {
		return rbac.MigrateAndSeed(tx)
	},
}

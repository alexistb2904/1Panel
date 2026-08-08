package migrations

import (
	"errors"
	"fmt"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// HardenCommunityRBACScopes upgrades early RBAC staging databases to the final
// node-aware binding schema and enforces one project owner per concrete
// resource. Existing resource bindings are conservatively treated as local
// (node 0), which is fail-closed for remote nodes.
var HardenCommunityRBACScopes = &gormigrate.Migration{
	ID: "20260807-harden-community-rbac-scopes",
	Migrate: func(tx *gorm.DB) error {
		// Add newly introduced columns before rebuilding composite indexes.
		if err := tx.AutoMigrate(&model.AccessRoleBinding{}, &model.AccessProjectResource{}); err != nil {
			return fmt.Errorf("prepare hardened RBAC schema: %w", err)
		}

		type duplicateOwner struct {
			NodeID       uint
			ResourceType string
			ResourceID   string
			Count        int64
		}
		var duplicates []duplicateOwner
		if err := tx.Model(&model.AccessProjectResource{}).
			Select("node_id, resource_type, resource_id, COUNT(*) AS count").
			Group("node_id, resource_type, resource_id").
			Having("COUNT(*) > 1").
			Scan(&duplicates).Error; err != nil {
			return fmt.Errorf("check duplicate project ownership: %w", err)
		}
		if len(duplicates) != 0 {
			first := duplicates[0]
			return errors.New(fmt.Sprintf("RBAC migration blocked: resource %d/%s/%s belongs to multiple projects; resolve duplicate ownership before upgrading", first.NodeID, first.ResourceType, first.ResourceID))
		}

		migrator := tx.Migrator()
		if migrator.HasIndex(&model.AccessRoleBinding{}, "idx_rbac_binding") {
			if err := migrator.DropIndex(&model.AccessRoleBinding{}, "idx_rbac_binding"); err != nil {
				return fmt.Errorf("drop legacy RBAC binding index: %w", err)
			}
		}
		if migrator.HasIndex(&model.AccessProjectResource{}, "idx_rbac_project_resource") {
			if err := migrator.DropIndex(&model.AccessProjectResource{}, "idx_rbac_project_resource"); err != nil {
				return fmt.Errorf("drop legacy project resource index: %w", err)
			}
		}
		if err := tx.AutoMigrate(&model.AccessRoleBinding{}, &model.AccessProjectResource{}); err != nil {
			return fmt.Errorf("create hardened RBAC indexes: %w", err)
		}
		return nil
	},
}

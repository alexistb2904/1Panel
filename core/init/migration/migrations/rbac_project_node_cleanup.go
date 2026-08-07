package migrations

import (
	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// CleanupImplicitLocalProjectNodes repairs early draft/staging databases that
// may have run the first project-node migration while it still attached every
// project to local node 0. An empty local boundary with no local-owned resource
// is not evidence of intended local access, so it is removed fail-closed.
var CleanupImplicitLocalProjectNodes = &gormigrate.Migration{
	ID: "20260807-cleanup-implicit-local-project-nodes",
	Migrate: func(tx *gorm.DB) error {
		if !tx.Migrator().HasTable(&model.AccessProjectNode{}) {
			return nil
		}
		var candidates []model.AccessProjectNode
		if err := tx.Where("node_id = ? AND (root_path = ? OR root_path IS NULL)", 0, "").Find(&candidates).Error; err != nil {
			return err
		}
		for _, boundary := range candidates {
			var localResources int64
			if err := tx.Model(&model.AccessProjectResource{}).
				Where("project_id = ? AND node_id = ?", boundary.ProjectID, 0).
				Count(&localResources).Error; err != nil {
				return err
			}
			if localResources == 0 {
				if err := tx.Delete(&boundary).Error; err != nil {
					return err
				}
			}
		}
		return nil
	},
}

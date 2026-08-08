package migrations

import (
	"errors"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/constant"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AddCommunityRBACProjectNodes makes the project/node relationship explicit.
// Existing concrete resource ownership seeds exactly the nodes on which a
// project already exists. A legacy non-empty RootPath additionally proves local
// node intent and is preserved as the local node-0 boundary. Empty remote-only
// projects are never implicitly attached to the master during upgrade.
//
// Direct resource-scope bindings are removed deliberately: stable human names
// are not immutable resource identities and could otherwise resurrect access
// after delete/recreate. Project scopes remain the supported scoped boundary.
//
// The legacy global API credential is disabled on upgrade. An administrator may
// consciously re-enable it later as a break-glass unrestricted credential.
var AddCommunityRBACProjectNodes = &gormigrate.Migration{
	ID: "20260807-add-community-rbac-project-nodes",
	Migrate: func(tx *gorm.DB) error {
		if err := tx.AutoMigrate(&model.AccessProjectNode{}); err != nil {
			return err
		}

		projects := make(map[uint]model.AccessProject)
		var projectRows []model.AccessProject
		if err := tx.Find(&projectRows).Error; err != nil {
			return err
		}
		for _, project := range projectRows {
			projects[project.ID] = project
			if strings.TrimSpace(project.RootPath) == "" {
				continue
			}
			item := model.AccessProjectNode{ProjectID: project.ID, NodeID: 0, RootPath: project.RootPath}
			if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "project_id"}, {Name: "node_id"}}, DoNothing: true}).Create(&item).Error; err != nil {
				return err
			}
		}

		type pair struct {
			ProjectID uint
			NodeID    uint
		}
		var pairs []pair
		if err := tx.Model(&model.AccessProjectResource{}).
			Select("DISTINCT project_id, node_id").
			Scan(&pairs).Error; err != nil {
			return err
		}
		for _, pair := range pairs {
			rootPath := ""
			if pair.NodeID == 0 {
				rootPath = projects[pair.ProjectID].RootPath
			}
			item := model.AccessProjectNode{ProjectID: pair.ProjectID, NodeID: pair.NodeID, RootPath: rootPath}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "project_id"}, {Name: "node_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"root_path"}),
			}).Create(&item).Error; err != nil {
				return err
			}
		}

		if err := tx.Where("scope_type = ?", model.AccessScopeResource).Delete(&model.AccessRoleBinding{}).Error; err != nil {
			return err
		}

		var apiStatus model.Setting
		if err := tx.Where("key = ?", "ApiInterfaceStatus").First(&apiStatus).Error; err == nil {
			if apiStatus.Value == constant.StatusEnable {
				if err := tx.Model(&apiStatus).Update("value", constant.StatusDisable).Error; err != nil {
					return err
				}
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return nil
	},
}

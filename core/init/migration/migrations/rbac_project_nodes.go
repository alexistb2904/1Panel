package migrations

import (
	"errors"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/constant"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AddCommunityRBACProjectNodes makes the project/node relationship explicit.
// Existing projects are attached to local node 0 and existing remote resource
// ownership rows seed the corresponding remote project-node attachment.
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

		var projects []model.AccessProject
		if err := tx.Find(&projects).Error; err != nil {
			return err
		}
		for _, project := range projects {
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
			item := model.AccessProjectNode{ProjectID: pair.ProjectID, NodeID: pair.NodeID}
			if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "project_id"}, {Name: "node_id"}}, DoNothing: true}).Create(&item).Error; err != nil {
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

package migrations

import (
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/constant"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAddCommunityRBACProjectNodesHardensExistingInstallation(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil { t.Fatal(err) }
	if err := db.AutoMigrate(&model.Setting{}, &model.AccessProject{}, &model.AccessProjectResource{}, &model.AccessRoleBinding{}); err != nil { t.Fatal(err) }

	project := model.AccessProject{Name: "Payments", Slug: "payments", RootPath: "/srv/payments", Status: "active"}
	if err := db.Create(&project).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessProjectResource{ProjectID: project.ID, NodeID: 42, ResourceType: "website", ResourceID: "website:api"}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessRoleBinding{UserID: 7, RoleID: 9, ScopeType: model.AccessScopeResource, ScopeID: "website:api", ResourceType: "website", NodeID: 42}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.Setting{Key: "ApiInterfaceStatus", Value: constant.StatusEnable}).Error; err != nil { t.Fatal(err) }

	if err := AddCommunityRBACProjectNodes.Migrate(db); err != nil { t.Fatal(err) }

	var local, remote model.AccessProjectNode
	if err := db.Where("project_id = ? AND node_id = ?", project.ID, 0).First(&local).Error; err != nil { t.Fatal(err) }
	if local.RootPath != "/srv/payments" { t.Fatalf("legacy local root was not preserved: %q", local.RootPath) }
	if err := db.Where("project_id = ? AND node_id = ?", project.ID, 42).First(&remote).Error; err != nil { t.Fatal(err) }

	var staleCount int64
	if err := db.Model(&model.AccessRoleBinding{}).Where("scope_type = ?", model.AccessScopeResource).Count(&staleCount).Error; err != nil { t.Fatal(err) }
	if staleCount != 0 { t.Fatalf("legacy direct resource bindings must be removed, got %d", staleCount) }

	var apiStatus model.Setting
	if err := db.Where("key = ?", "ApiInterfaceStatus").First(&apiStatus).Error; err != nil { t.Fatal(err) }
	if apiStatus.Value != constant.StatusDisable { t.Fatalf("legacy global API credential must be disabled on RBAC upgrade, got %q", apiStatus.Value) }
}

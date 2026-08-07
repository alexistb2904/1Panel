package rbac

import (
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAccessibleResourceIDsSeparatesLocalAndRemoteNodes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.AccessUser{}, &model.AccessRole{}, &model.AccessPermission{}, &model.AccessRolePermission{}, &model.AccessRoleBinding{}, &model.AccessProject{}, &model.AccessProjectResource{}); err != nil {
		t.Fatal(err)
	}
	user := model.AccessUser{Username: "dev", PasswordHash: "!", Status: model.AccessUserStatusActive, AuthSource: "local"}
	role := model.AccessRole{Key: RoleDeveloper, Name: "Developer"}
	permission := model.AccessPermission{Code: "website.view", ResourceType: "website", Feature: "website", Action: "view", RiskLevel: "low"}
	project := model.AccessProject{Name: "App", Slug: "app", Status: "active"}
	for _, item := range []any{&user, &role, &permission, &project} {
		if err := db.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&model.AccessRolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.AccessRoleBinding{UserID: user.ID, RoleID: role.ID, ScopeType: model.AccessScopeProject, ScopeID: "1"}).Error; err != nil {
		t.Fatal(err)
	}
	resources := []model.AccessProjectResource{
		{ProjectID: project.ID, NodeID: 0, ResourceType: "website", ResourceID: "website:local"},
		{ProjectID: project.ID, NodeID: 42, ResourceType: "website", ResourceID: "website:remote"},
	}
	for i := range resources {
		if err := db.Create(&resources[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	evaluator := NewEvaluator(db)
	local, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(local.IDs) != 1 || local.IDs[0] != "website:local" {
		t.Fatalf("local scope leaked remote resources: %#v", local.IDs)
	}
	remote, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(remote.IDs) != 1 || remote.IDs[0] != "website:remote" {
		t.Fatalf("remote scope leaked local resources: %#v", remote.IDs)
	}
}

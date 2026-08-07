package rbac

import (
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newEvaluatorTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil { t.Fatal(err) }
	if err := db.AutoMigrate(&model.AccessUser{}, &model.AccessRole{}, &model.AccessPermission{}, &model.AccessRolePermission{}, &model.AccessRoleBinding{}, &model.AccessProject{}, &model.AccessProjectResource{}); err != nil { t.Fatal(err) }
	return db
}

func TestAccessibleResourceIDsSeparatesLocalAndRemoteNodes(t *testing.T) {
	db := newEvaluatorTestDB(t)
	user := model.AccessUser{Username: "dev", PasswordHash: "!", Status: model.AccessUserStatusActive, AuthSource: "local"}
	role := model.AccessRole{Key: RoleDeveloper, Name: "Developer"}
	permission := model.AccessPermission{Code: "website.view", ResourceType: "website", Feature: "website", Action: "view", RiskLevel: "low"}
	project := model.AccessProject{Name: "App", Slug: "app", Status: "active"}
	for _, item := range []any{&user, &role, &permission, &project} { if err := db.Create(item).Error; err != nil { t.Fatal(err) } }
	if err := db.Create(&model.AccessRolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessRoleBinding{UserID: user.ID, RoleID: role.ID, ScopeType: model.AccessScopeProject, ScopeID: "1"}).Error; err != nil { t.Fatal(err) }
	resources := []model.AccessProjectResource{{ProjectID: project.ID, NodeID: 0, ResourceType: "website", ResourceID: "website:local"}, {ProjectID: project.ID, NodeID: 42, ResourceType: "website", ResourceID: "website:remote"}}
	for i := range resources { if err := db.Create(&resources[i]).Error; err != nil { t.Fatal(err) } }
	evaluator := NewEvaluator(db)
	local, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 0)
	if err != nil { t.Fatal(err) }
	if len(local.IDs) != 1 || local.IDs[0] != "website:local" { t.Fatalf("local scope leaked remote resources: %#v", local.IDs) }
	remote, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 42)
	if err != nil { t.Fatal(err) }
	if len(remote.IDs) != 1 || remote.IDs[0] != "website:remote" { t.Fatalf("remote scope leaked local resources: %#v", remote.IDs) }
}

func TestResourceBindingIsBoundToExactNode(t *testing.T) {
	db := newEvaluatorTestDB(t)
	user := model.AccessUser{Username: "resource-dev", PasswordHash: "!", Status: model.AccessUserStatusActive, AuthSource: "local"}
	role := model.AccessRole{Key: RoleDeveloper, Name: "Developer"}
	permission := model.AccessPermission{Code: "website.view", ResourceType: "website", Feature: "website", Action: "view", RiskLevel: "low"}
	for _, item := range []any{&user, &role, &permission} { if err := db.Create(item).Error; err != nil { t.Fatal(err) } }
	if err := db.Create(&model.AccessRolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessRoleBinding{UserID: user.ID, RoleID: role.ID, ScopeType: model.AccessScopeResource, ScopeID: "website:api", ResourceType: "website", NodeID: 42}).Error; err != nil { t.Fatal(err) }
	evaluator := NewEvaluator(db)
	local, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 0)
	if err != nil { t.Fatal(err) }
	if len(local.IDs) != 0 { t.Fatalf("remote resource binding leaked to local node: %#v", local.IDs) }
	remote, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 42)
	if err != nil { t.Fatal(err) }
	if len(remote.IDs) != 1 || remote.IDs[0] != "website:api" { t.Fatalf("remote resource binding missing on its node: %#v", remote.IDs) }
	allowed, err := evaluator.Can(user.ID, "website.view", ResourceContext{NodeID: 0, Type: "website", ID: "website:api"})
	if err != nil { t.Fatal(err) }
	if allowed { t.Fatal("resource binding must not match the same stable ID on another node") }
}

func TestCanGlobalRejectsNodeScopedPermission(t *testing.T) {
	db := newEvaluatorTestDB(t)
	user := model.AccessUser{Username: "security", PasswordHash: "!", Status: model.AccessUserStatusActive, AuthSource: "local"}
	role := model.AccessRole{Key: RoleSecurityAdvisor, Name: "Security Advisor"}
	permission := model.AccessPermission{Code: "audit.view", ResourceType: "audit", Feature: "audit", Action: "view", RiskLevel: "medium"}
	for _, item := range []any{&user, &role, &permission} { if err := db.Create(item).Error; err != nil { t.Fatal(err) } }
	if err := db.Create(&model.AccessRolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessRoleBinding{UserID: user.ID, RoleID: role.ID, ScopeType: model.AccessScopeNode, ScopeID: "0"}).Error; err != nil { t.Fatal(err) }
	allowed, err := NewEvaluator(db).CanGlobal(user.ID, "audit.view")
	if err != nil { t.Fatal(err) }
	if allowed { t.Fatal("node-scoped permission must not satisfy a global guard") }
}

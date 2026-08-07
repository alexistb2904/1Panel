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
	if err := db.AutoMigrate(&model.AccessUser{}, &model.AccessRole{}, &model.AccessPermission{}, &model.AccessRolePermission{}, &model.AccessRoleBinding{}, &model.AccessProject{}, &model.AccessProjectNode{}, &model.AccessProjectResource{}); err != nil { t.Fatal(err) }
	return db
}

func seedProjectPermission(t *testing.T, db *gorm.DB, code string) (model.AccessUser, model.AccessProject) {
	t.Helper()
	user := model.AccessUser{Username: "dev-" + code, PasswordHash: "!", Status: model.AccessUserStatusActive, AuthSource: "local"}
	role := model.AccessRole{Key: RoleDeveloper + "-" + code, Name: "Developer"}
	permission := model.AccessPermission{Code: code, ResourceType: "website", Feature: "website", Action: "view", RiskLevel: "low"}
	project := model.AccessProject{Name: "App", Slug: "app-" + code, Status: "active"}
	for _, item := range []any{&user, &role, &permission, &project} { if err := db.Create(item).Error; err != nil { t.Fatal(err) } }
	if err := db.Create(&model.AccessRolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessRoleBinding{UserID: user.ID, RoleID: role.ID, ScopeType: model.AccessScopeProject, ScopeID: stringUint(uint(project.ID))}).Error; err != nil { t.Fatal(err) }
	return user, project
}

func TestAccessibleResourceIDsRequiresProjectNodeAttachment(t *testing.T) {
	db := newEvaluatorTestDB(t)
	user, project := seedProjectPermission(t, db, "website.view")
	if err := db.Create(&model.AccessProjectNode{ProjectID: project.ID, NodeID: 0, RootPath: "/srv/local"}).Error; err != nil { t.Fatal(err) }
	resources := []model.AccessProjectResource{
		{ProjectID: project.ID, NodeID: 0, ResourceType: "website", ResourceID: "website:local"},
		{ProjectID: project.ID, NodeID: 42, ResourceType: "website", ResourceID: "website:remote"},
	}
	for i := range resources { if err := db.Create(&resources[i]).Error; err != nil { t.Fatal(err) } }

	evaluator := NewEvaluator(db)
	local, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 0)
	if err != nil { t.Fatal(err) }
	if len(local.IDs) != 1 || local.IDs[0] != "website:local" { t.Fatalf("unexpected local scope: %#v", local.IDs) }
	remote, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 42)
	if err != nil { t.Fatal(err) }
	if len(remote.IDs) != 0 { t.Fatalf("project not attached to node 42 must have no remote resources: %#v", remote.IDs) }

	if err := db.Create(&model.AccessProjectNode{ProjectID: project.ID, NodeID: 42, RootPath: "/srv/remote"}).Error; err != nil { t.Fatal(err) }
	remote, err = evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 42)
	if err != nil { t.Fatal(err) }
	if len(remote.IDs) != 1 || remote.IDs[0] != "website:remote" { t.Fatalf("attached remote resource missing: %#v", remote.IDs) }
}

func TestProjectContextCannotAuthorizeUnattachedNode(t *testing.T) {
	db := newEvaluatorTestDB(t)
	user, project := seedProjectPermission(t, db, "website.create")
	if err := db.Create(&model.AccessProjectNode{ProjectID: project.ID, NodeID: 0}).Error; err != nil { t.Fatal(err) }
	evaluator := NewEvaluator(db)
	allowed, err := evaluator.Can(user.ID, "website.create", ResourceContext{NodeID: 42, ProjectID: project.ID, Type: "project", ID: stringUint(project.ID)})
	if err != nil { t.Fatal(err) }
	if allowed { t.Fatal("project scope must not authorize a node the project is not attached to") }
	if err := db.Create(&model.AccessProjectNode{ProjectID: project.ID, NodeID: 42}).Error; err != nil { t.Fatal(err) }
	allowed, err = evaluator.Can(user.ID, "website.create", ResourceContext{NodeID: 42, ProjectID: project.ID, Type: "project", ID: stringUint(project.ID)})
	if err != nil { t.Fatal(err) }
	if !allowed { t.Fatal("attached project node should authorize the project context") }
}

func TestStaleDirectResourceBindingIsIgnored(t *testing.T) {
	db := newEvaluatorTestDB(t)
	user := model.AccessUser{Username: "resource-dev", PasswordHash: "!", Status: model.AccessUserStatusActive, AuthSource: "local"}
	role := model.AccessRole{Key: "legacy-resource-role", Name: "Legacy"}
	permission := model.AccessPermission{Code: "website.view", ResourceType: "website", Feature: "website", Action: "view", RiskLevel: "low"}
	for _, item := range []any{&user, &role, &permission} { if err := db.Create(item).Error; err != nil { t.Fatal(err) } }
	if err := db.Create(&model.AccessRolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessRoleBinding{UserID: user.ID, RoleID: role.ID, ScopeType: model.AccessScopeResource, ScopeID: "website:api", ResourceType: "website", NodeID: 42}).Error; err != nil { t.Fatal(err) }
	evaluator := NewEvaluator(db)
	filter, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 42)
	if err != nil { t.Fatal(err) }
	if len(filter.IDs) != 0 { t.Fatalf("stale direct resource binding must be ignored: %#v", filter.IDs) }
	allowed, err := evaluator.Can(user.ID, "website.view", ResourceContext{NodeID: 42, Type: "website", ID: "website:api"})
	if err != nil { t.Fatal(err) }
	if allowed { t.Fatal("direct stable-name grant must never authorize after hardening") }
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

package rbac

import (
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
)

func TestPendingOwnershipNeverAuthorizes(t *testing.T) {
	db := newEvaluatorTestDB(t)
	user, project := seedProjectPermission(t, db, "website.view")
	if err := db.Create(&model.AccessProjectNode{ProjectID: project.ID, NodeID: 0}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessProjectResource{ProjectID: project.ID, NodeID: 0, ResourceType: "website", ResourceID: "website:pending", State: model.AccessResourceStatePending}).Error; err != nil { t.Fatal(err) }

	evaluator := NewEvaluator(db)
	filter, err := evaluator.AccessibleResourceIDs(user.ID, "website.view", "website", 0)
	if err != nil { t.Fatal(err) }
	if len(filter.IDs) != 0 { t.Fatalf("pending reservation leaked into accessible filter: %#v", filter.IDs) }
	allowed, err := evaluator.Can(user.ID, "website.view", ResourceContext{NodeID: 0, ProjectID: project.ID, Type: "website", ID: "website:pending"})
	if err != nil { t.Fatal(err) }
	if allowed { t.Fatal("pending resource ownership must never authorize") }
}

func TestExplicitProjectIDMustMatchConcreteResourceOwnership(t *testing.T) {
	db := newEvaluatorTestDB(t)
	user, projectA := seedProjectPermission(t, db, "runtime.edit")
	projectB := model.AccessProject{Name: "Other", Slug: "other-runtime-edit", Status: "active"}
	if err := db.Create(&projectB).Error; err != nil { t.Fatal(err) }
	for _, project := range []model.AccessProject{projectA, projectB} {
		if err := db.Create(&model.AccessProjectNode{ProjectID: project.ID, NodeID: 0}).Error; err != nil { t.Fatal(err) }
	}
	// Make project B genuinely accessible to the user. Before hardening, the
	// supplied ProjectID would then short-circuit concrete resource membership
	// and incorrectly authorize project A's resource as if it belonged to B.
	var original model.AccessRoleBinding
	if err := db.Where("user_id = ? AND scope_type = ? AND scope_id = ?", user.ID, model.AccessScopeProject, stringUint(projectA.ID)).First(&original).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessRoleBinding{UserID: user.ID, RoleID: original.RoleID, ScopeType: model.AccessScopeProject, ScopeID: stringUint(projectB.ID)}).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessProjectResource{ProjectID: projectA.ID, NodeID: 0, ResourceType: "website", ResourceID: "runtime:alpha", State: model.AccessResourceStateActive}).Error; err != nil { t.Fatal(err) }

	allowed, err := NewEvaluator(db).Can(user.ID, "runtime.edit", ResourceContext{
		NodeID: 0, ProjectID: projectB.ID, Type: "website", ID: "runtime:alpha",
	})
	if err != nil { t.Fatal(err) }
	if allowed { t.Fatal("supplying another accessible project ID must not authorize a resource owned by project A") }
}

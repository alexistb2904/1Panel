package rbac

import (
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func withScopedApplicationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.AccessProject{}, &model.AccessProjectResource{}); err != nil {
		t.Fatal(err)
	}
	previous := global.DB
	global.DB = db
	t.Cleanup(func() { global.DB = previous })
	return db
}

func TestProjectForScopedResourceBindsProjectAndStableResourceTogether(t *testing.T) {
	db := withScopedApplicationDB(t)
	projectA := model.AccessProject{Name: "A", Slug: "a", Status: "active"}
	projectB := model.AccessProject{Name: "B", Slug: "b", Status: "active"}
	if err := db.Create(&projectA).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&projectB).Error; err != nil {
		t.Fatal(err)
	}
	membership := model.AccessProjectResource{
		ProjectID: projectA.ID,
		NodeID: 0,
		ResourceType: "runtime",
		ResourceID: "runtime:worker",
		State: model.AccessResourceStateActive,
	}
	if err := db.Create(&membership).Error; err != nil {
		t.Fatal(err)
	}

	project, err := projectForScopedResource(0, "runtime", "runtime:worker", projectA.ID)
	if err != nil || project.ID != projectA.ID {
		t.Fatalf("canonical owner should resolve: project=%d err=%v", project.ID, err)
	}
	if _, err := projectForScopedResource(0, "runtime", "runtime:worker", projectB.ID); err == nil {
		t.Fatal("explicit project must not override the concrete resource owner")
	}
	if _, err := projectForScopedResource(0, "runtime", "", projectA.ID); err == nil {
		t.Fatal("project ID alone must never be sufficient to select an arbitrary resource root")
	}
}

func TestRuntimeUpdateClassifierUsesStableNameForOwnershipChecks(t *testing.T) {
	payload := map[string]any{
		"id": float64(42),
		"name": "worker",
		"projectID": float64(7),
		"codeDir": "/srv/project/app",
	}
	req := classifyRuntimeCoreRequest("POST", "/api/v2/runtimes/update", payload)
	if req.ResourceID != "runtime:worker" {
		t.Fatalf("runtime update must use stable ownership identity, got %q", req.ResourceID)
	}
	if !req.NeedsRoot {
		t.Fatal("host-path mutation must still be classified as requiring a project root")
	}
}

func TestBuiltInNonAdminRolesDoNotAdvertiseScopedFileManager(t *testing.T) {
	for _, role := range DefaultRoleDefinitions {
		if role.Key == RoleAdministrator {
			continue
		}
		for _, permission := range role.Permissions {
			if permission == "website.files.read" || permission == "website.files.write" || permission == "website.files.delete" {
				t.Fatalf("role %s still advertises raceable scoped filesystem permission %s", role.Key, permission)
			}
		}
	}
}

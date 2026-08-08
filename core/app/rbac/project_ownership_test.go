package rbac

import (
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestProjectResourceUniqueOwnerPerNodeTypeAndID(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil { t.Fatal(err) }
	if err := db.AutoMigrate(&model.AccessProjectResource{}); err != nil { t.Fatal(err) }
	first := model.AccessProjectResource{ProjectID: 1, NodeID: 42, ResourceType: "website", ResourceID: "website:api"}
	if err := db.Create(&first).Error; err != nil { t.Fatal(err) }
	second := model.AccessProjectResource{ProjectID: 2, NodeID: 42, ResourceType: "website", ResourceID: "website:api"}
	if err := db.Create(&second).Error; err == nil {
		t.Fatal("the same concrete resource must not be owned by two projects")
	}
	otherNode := model.AccessProjectResource{ProjectID: 2, NodeID: 43, ResourceType: "website", ResourceID: "website:api"}
	if err := db.Create(&otherNode).Error; err != nil {
		t.Fatalf("same stable resource ID on another node must remain distinct: %v", err)
	}
}

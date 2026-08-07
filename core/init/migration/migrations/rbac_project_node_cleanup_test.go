package migrations

import (
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestCleanupImplicitLocalProjectNodesRemovesOnlyUnprovenLocalAttachment(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil { t.Fatal(err) }
	if err := db.AutoMigrate(&model.AccessProjectNode{}, &model.AccessProjectResource{}); err != nil { t.Fatal(err) }

	implicit := model.AccessProjectNode{ProjectID: 1, NodeID: 0, RootPath: ""}
	localOwned := model.AccessProjectNode{ProjectID: 2, NodeID: 0, RootPath: ""}
	explicitRoot := model.AccessProjectNode{ProjectID: 3, NodeID: 0, RootPath: "/srv/project-three"}
	for _, item := range []*model.AccessProjectNode{&implicit, &localOwned, &explicitRoot} {
		if err := db.Create(item).Error; err != nil { t.Fatal(err) }
	}
	if err := db.Create(&model.AccessProjectResource{ProjectID: 2, NodeID: 0, ResourceType: "website", ResourceID: "website:local"}).Error; err != nil { t.Fatal(err) }

	if err := CleanupImplicitLocalProjectNodes.Migrate(db); err != nil { t.Fatal(err) }

	var count int64
	if err := db.Model(&model.AccessProjectNode{}).Where("project_id = ? AND node_id = 0", 1).Count(&count).Error; err != nil { t.Fatal(err) }
	if count != 0 { t.Fatal("empty local boundary without local resources must be removed") }
	if err := db.Model(&model.AccessProjectNode{}).Where("project_id = ? AND node_id = 0", 2).Count(&count).Error; err != nil { t.Fatal(err) }
	if count != 1 { t.Fatal("local boundary backed by a local-owned resource must be preserved") }
	if err := db.Model(&model.AccessProjectNode{}).Where("project_id = ? AND node_id = 0", 3).Count(&count).Error; err != nil { t.Fatal(err) }
	if count != 1 { t.Fatal("explicit local root boundary must be preserved") }
}

package rbac

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func withOwnershipTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil { t.Fatal(err) }
	if err := db.AutoMigrate(&model.AccessProjectResource{}, &model.AccessAuditEvent{}); err != nil { t.Fatal(err) }
	return db
}

func TestContinueCreationWithOwnershipActivatesOnlyAfterSuccess(t *testing.T) {
	db := withOwnershipTestDB(t)
	previous := global.DB
	global.DB = db
	defer func() { global.DB = previous }()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/create",
		func(c *gin.Context) { ContinueCreationWithOwnership(c, 7, 0, "website", "website:ok") },
		func(c *gin.Context) {
			var pending int64
			if err := db.Model(&model.AccessProjectResource{}).
				Where("project_id = ? AND resource_id = ? AND state = ?", 7, "website:ok", model.AccessResourceStatePending).
				Count(&pending).Error; err != nil { t.Fatal(err) }
			if pending != 1 { t.Fatalf("downstream must execute with exactly one non-authorizing pending reservation, got %d", pending) }
			c.JSON(http.StatusOK, gin.H{"code": 200})
		},
	)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/create", nil))
	var resource model.AccessProjectResource
	if err := db.Where("project_id = ? AND node_id = ? AND resource_type = ? AND resource_id = ?", 7, 0, "website", "website:ok").First(&resource).Error; err != nil { t.Fatal(err) }
	if resource.State != model.AccessResourceStateActive { t.Fatalf("successful creation must activate ownership, got %q", resource.State) }
	projectResourceCreationLocks.Lock()
	locks := len(projectResourceCreationLocks.items)
	projectResourceCreationLocks.Unlock()
	if locks != 0 { t.Fatalf("creation keyed locks must be released, got %d retained entries", locks) }
}

func TestContinueCreationWithOwnershipDoesNotPersistOnBusinessFailure(t *testing.T) {
	db := withOwnershipTestDB(t)
	previous := global.DB
	global.DB = db
	defer func() { global.DB = previous }()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/create",
		func(c *gin.Context) { ContinueCreationWithOwnership(c, 7, 0, "website", "website:failed") },
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"code": 500, "message": "failed"}) },
	)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/create", nil))
	var count int64
	if err := db.Model(&model.AccessProjectResource{}).Where("resource_id = ?", "website:failed").Count(&count).Error; err != nil { t.Fatal(err) }
	if count != 0 { t.Fatalf("failed creation must not leave pending or active ownership, got count=%d", count) }
}

func TestContinueCreationWithOwnershipRejectsConflictingProject(t *testing.T) {
	db := withOwnershipTestDB(t)
	if err := db.Create(&model.AccessProjectResource{ProjectID: 9, NodeID: 0, ResourceType: "website", ResourceID: "website:shared", State: model.AccessResourceStateActive}).Error; err != nil { t.Fatal(err) }
	previous := global.DB
	global.DB = db
	defer func() { global.DB = previous }()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	called := false
	router.POST("/create",
		func(c *gin.Context) { ContinueCreationWithOwnership(c, 7, 0, "website", "website:shared") },
		func(c *gin.Context) { called = true; c.JSON(http.StatusOK, gin.H{"code": 200}) },
	)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/create", nil))
	if called { t.Fatal("downstream creation must not run when another project already owns the resource") }
}

package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func withFinalGuardTestDB(t *testing.T) (*gorm.DB, model.AccessUser) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil { t.Fatal(err) }
	if err := db.AutoMigrate(&model.AccessUser{}, &model.AccessRole{}, &model.AccessPermission{}, &model.AccessRolePermission{}, &model.AccessRoleBinding{}, &model.AccessAuditEvent{}); err != nil { t.Fatal(err) }
	user := model.AccessUser{Username: "restricted", PasswordHash: "!", Status: model.AccessUserStatusActive, AuthSource: "local"}
	if err := db.Create(&user).Error; err != nil { t.Fatal(err) }
	return db, user
}

func TestFinalDefaultDenyBlocksLegacyAgentAPI(t *testing.T) {
	db, user := withFinalGuardTestDB(t)
	previous := global.DB
	global.DB = db
	defer func() { global.DB = previous }()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set(GinContextAccessUserIDKey, user.ID); c.Next() })
	router.Use(FinalDefaultDenyMiddleware())
	router.GET("/api/v2/hosts/terminal/local", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"code": 200}) })

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v2/hosts/terminal/local", nil)
	router.ServeHTTP(recorder, req)
	var body struct{ Code int `json:"code"` }
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil { t.Fatal(err) }
	if body.Code != http.StatusForbidden { t.Fatalf("legacy Agent API must be default-denied, got %d body=%s", body.Code, recorder.Body.String()) }
}

func TestFinalDefaultDenyAllowsExplicitlyScopedFamily(t *testing.T) {
	db, user := withFinalGuardTestDB(t)
	previous := global.DB
	global.DB = db
	defer func() { global.DB = previous }()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set(GinContextAccessUserIDKey, user.ID); c.Next() })
	router.Use(FinalDefaultDenyMiddleware())
	router.POST("/api/v2/websites/search", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"code": 200}) })

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v2/websites/search", nil)
	router.ServeHTTP(recorder, req)
	var body struct{ Code int `json:"code"` }
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil { t.Fatal(err) }
	if body.Code != http.StatusOK { t.Fatalf("explicit scoped family should pass final guard, got %d", body.Code) }
}

func TestFinalDefaultDenyAllowsGlobalAdministrator(t *testing.T) {
	db, user := withFinalGuardTestDB(t)
	role := model.AccessRole{Key: RoleAdministrator, Name: "Administrator"}
	if err := db.Create(&role).Error; err != nil { t.Fatal(err) }
	if err := db.Create(&model.AccessRoleBinding{UserID: user.ID, RoleID: role.ID, ScopeType: model.AccessScopeGlobal, ScopeID: "*"}).Error; err != nil { t.Fatal(err) }
	previous := global.DB
	global.DB = db
	defer func() { global.DB = previous }()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set(GinContextAccessUserIDKey, user.ID); c.Next() })
	router.Use(FinalDefaultDenyMiddleware())
	router.GET("/api/v2/hosts/terminal/local", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"code": 200}) })

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v2/hosts/terminal/local", nil)
	router.ServeHTTP(recorder, req)
	var body struct{ Code int `json:"code"` }
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil { t.Fatal(err) }
	if body.Code != http.StatusOK { t.Fatalf("global administrator should bypass final guard, got %d", body.Code) }
}

package rbac

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func withAuthHardeningDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.AccessUser{}, &model.Setting{}, &model.AccessAuditEvent{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func withGlobalDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	previous := global.DB
	global.DB = db
	t.Cleanup(func() { global.DB = previous })
}

func TestCommunityRBACEnabledRemainsTrueWithZeroUsers(t *testing.T) {
	db := withAuthHardeningDB(t)
	withGlobalDB(t, db)
	if !CommunityRBACEnabled() {
		t.Fatal("an existing RBAC schema must permanently disable legacy authentication even when no users remain")
	}
}

func TestLegacyLoginCannotResurrectWhenRBACUserMissing(t *testing.T) {
	db := withAuthHardeningDB(t)
	withGlobalDB(t, db)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	downstream := false
	router.POST("/login", RejectLegacyLoginAfterRBAC(), func(c *gin.Context) { downstream = true; c.Status(http.StatusNoContent) })
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"name":"old-admin"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	if downstream {
		t.Fatal("unknown user must not fall through to legacy Settings credentials after migration")
	}
	if !strings.Contains(recorder.Body.String(), `"code":401`) {
		t.Fatalf("expected fail-closed authentication response, got %s", recorder.Body.String())
	}
}

func TestServiceAccountCannotUseInteractiveProfileRoutes(t *testing.T) {
	db := withAuthHardeningDB(t)
	withGlobalDB(t, db)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/current", func(c *gin.Context) { c.Set("SCOPED_API_AUTH", true); c.Next() }, RequireInteractiveUser(), func(c *gin.Context) { t.Fatal("service account reached interactive handler") })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/current", nil))
	if !strings.Contains(recorder.Body.String(), `"code":403`) {
		t.Fatalf("expected service-account 403, got %s", recorder.Body.String())
	}
}

func TestSelfServicePasswordMinimumIsServerEnforced(t *testing.T) {
	db := withAuthHardeningDB(t)
	withGlobalDB(t, db)
	gin.SetMode(gin.TestMode)
	encoded := base64.StdEncoding.EncodeToString([]byte("short"))
	body := `{"name":"valid-user","password":"` + encoded + `"}`
	router := gin.New()
	router.POST("/update", ValidateCurrentUserUpdate(), func(c *gin.Context) { t.Fatal("short password reached update handler") })
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/update", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	if !strings.Contains(recorder.Body.String(), `"code":400`) {
		t.Fatalf("expected password policy rejection, got %s", recorder.Body.String())
	}
}

func TestLoginLanguageIsNormalizedWithoutMutatingGlobalSetting(t *testing.T) {
	db := withAuthHardeningDB(t)
	withGlobalDB(t, db)
	if err := db.Create(&model.Setting{Key: "Language", Value: "en"}).Error; err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/login", PreserveGlobalLanguageOnLogin(), func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["language"] != "en" {
			t.Fatalf("login language was not normalized to persisted value: %#v", payload["language"])
		}
		c.JSON(http.StatusOK, gin.H{"code": 200})
	})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"name":"someone","language":"fr"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	var setting model.Setting
	if err := db.Where("key = ?", "Language").First(&setting).Error; err != nil {
		t.Fatal(err)
	}
	if setting.Value != "en" {
		t.Fatalf("unauthenticated login request changed global language: %q", setting.Value)
	}
}

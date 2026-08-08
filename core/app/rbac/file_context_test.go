package rbac

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPublicFileShareRoutesBypassAuthenticatedFileRBAC(t *testing.T) {
	for _, path := range []string{
		"/api/v2/files/share/info",
		"/api/v2/files/share/check",
		"/api/v2/files/share/download",
	} {
		if !isPublicFileShareRBACBypass(path) { t.Fatalf("public share route %s must bypass session RBAC", path) }
	}
	for _, path := range []string{
		"/api/v2/files/share/search",
		"/api/v2/files/share/create",
		"/api/v2/files/share/del",
	} {
		if isPublicFileShareRBACBypass(path) { t.Fatalf("authenticated share-management route %s must not be public", path) }
	}
}

func TestPublicFileShareActuallyTraversesFileAuthorizationMiddlewareWithoutIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(FileAuthorizationMiddleware())
	router.GET("/api/v2/files/share/info", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v2/files/share/info", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("anonymous public share must reach downstream handler, got HTTP %d", recorder.Code)
	}
}

func TestRestrictedFilePermissionDoesNotExposeRemoteFetchOrLongRunningTasks(t *testing.T) {
	for _, path := range []string{
		"/api/v2/files/wget",
		"/api/v2/files/compress",
		"/api/v2/files/convert",
	} {
		if permission, ok := filePermissionForRequest(http.MethodPost, path); ok || permission != "" {
			t.Fatalf("%s must be administrator-only, got permission=%q ok=%v", path, permission, ok)
		}
	}
}

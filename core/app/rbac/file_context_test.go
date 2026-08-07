package rbac

import (
	"net/http"
	"testing"
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

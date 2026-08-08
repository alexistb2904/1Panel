package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestScopedComposeRejectsRelativeHostBind(t *testing.T) {
	compose := `services:
  app:
    image: alpine
    volumes:
      - ./data:/data
`
	if err := rejectScopedComposeHostPaths(compose); err == nil {
		t.Fatal("relative host bind must be rejected for scoped Compose")
	}
}

func TestScopedComposeRejectsAbsoluteHostBind(t *testing.T) {
	compose := `services:
  app:
    image: alpine
    volumes:
      - /srv/project/data:/data
`
	if err := rejectScopedComposeHostPaths(compose); err == nil {
		t.Fatal("absolute host bind must be rejected for scoped Compose")
	}
}

func TestScopedComposeAllowsDeclaredNamedVolume(t *testing.T) {
	compose := `services:
  app:
    image: alpine
    volumes:
      - data:/data
volumes:
  data: {}
`
	if err := rejectScopedComposeHostPaths(compose); err != nil {
		t.Fatalf("declared project-local named volume should remain available: %v", err)
	}
}

func TestScopedDirectContainerRejectsHostBindBeforeHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	reached := false
	router.POST("/api/v2/containers", DockerScopedHostPathGuard(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	body := `{"name":"app","image":"alpine","volumes":[{"type":"bind","sourceDir":"/srv/project/data","containerDir":"/data"}]}`
	// Use actual JSON on the wire.
	body = "{\"name\":\"app\",\"image\":\"alpine\",\"volumes\":[{\"type\":\"bind\",\"sourceDir\":\"/srv/project/data\",\"containerDir\":\"/data\"}]}"
	req := httptest.NewRequest(http.MethodPost, "/api/v2/containers", strings.NewReader(body))
	req.Header.Set(headerDockerRBACMode, dockerRBACModeIDs)
	req.Header.Set(headerDockerRBACRestricted, "1")
	router.ServeHTTP(recorder, req)
	if reached {
		t.Fatal("scoped host bind reached Docker handler")
	}
	if !strings.Contains(recorder.Body.String(), "Host bind mounts are administrator-only") {
		t.Fatalf("unexpected scoped bind rejection: %s", recorder.Body.String())
	}
}

func TestFreshScopedWebsiteAliasRejectsTraversalAndStaleState(t *testing.T) {
	root := t.TempDir()
	for _, alias := range []string{"../other", "a/b", ".", "..", "with space"} {
		if err := validateFreshScopedWebsiteAlias(alias, root); err == nil {
			t.Fatalf("unsafe scoped website alias was accepted: %q", alias)
		}
	}
	if err := validateFreshScopedWebsiteAlias("fresh-site", root); err != nil {
		t.Fatalf("fresh safe alias rejected: %v", err)
	}
	stale := filepath.Join(root, "stale-site")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateFreshScopedWebsiteAlias("stale-site", root); err == nil {
		t.Fatal("pre-existing website filesystem state must not be adopted by a new ownership grant")
	}
}

func TestRestrictedRuntimeGenericUpdateIsDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	reached := false
	router.POST("/api/v2/runtimes/update", RuntimeRestrictedExecution(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v2/runtimes/update", strings.NewReader(`{}`))
	req.Header.Set(headerRBACMode, rbacModeIDs)
	router.ServeHTTP(recorder, req)
	if reached {
		t.Fatal("scoped generic runtime mutation reached handler")
	}
	if !strings.Contains(recorder.Body.String(), "Generic runtime mutation is administrator-only") {
		t.Fatalf("unexpected runtime rejection: %s", recorder.Body.String())
	}
}

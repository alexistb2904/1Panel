package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPathWithinAnyProjectRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "site", "index.html")
	if _, _, ok := pathWithinAnyProjectRoot(inside, []string{root}); !ok {
		t.Fatalf("expected %s to be inside project root", inside)
	}
	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if _, _, ok := pathWithinAnyProjectRoot(outside, []string{root}); ok {
		t.Fatalf("outside path must not be authorized")
	}
	if _, _, ok := pathWithinAnyProjectRoot(filepath.Join(root, "..", "escape"), []string{root}); ok {
		t.Fatalf("traversal path must not be authorized")
	}
}

func TestSecureCanonicalPathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	target := filepath.Join(link, "new-file.txt")
	if _, _, ok := pathWithinAnyProjectRoot(target, []string{root}); ok {
		t.Fatalf("symlink escape must not be authorized")
	}
}

func TestDecodeRBACRootsSkipsSystemRoot(t *testing.T) {
	data, err := json.Marshal([]string{"/"})
	if err != nil { t.Fatal(err) }
	encoded := base64.RawURLEncoding.EncodeToString(data)
	roots, err := decodeRBACRoots(encoded)
	if err != nil { t.Fatal(err) }
	if len(roots) != 0 { t.Fatalf("system root must be discarded, got %v", roots) }
}

func restrictedFileContext(method, path string, body []byte) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(method, path, bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c
}

func TestRestrictedFileOperationRejectsOwnerAndModeChanges(t *testing.T) {
	for _, path := range []string{"/api/v2/files/owner", "/api/v2/files/mode", "/api/v2/files/batch/role"} {
		c := restrictedFileContext(http.MethodPost, path, []byte(`{"path":"/tmp/project/file"}`))
		if err := validateRestrictedFileOperation(c); err == nil {
			t.Fatalf("%s must be administrator-only", path)
		}
	}
}

func TestRestrictedFileOperationRejectsSpecialPermissionBits(t *testing.T) {
	c := restrictedFileContext(http.MethodPost, "/api/v2/files", []byte(`{"path":"/tmp/project/tool","mode":2541}`)) // 04755
	if err := validateRestrictedFileOperation(c); err == nil {
		t.Fatal("SUID/SGID/sticky bits must be rejected for restricted file creation")
	}
}

func TestRestrictedFileOperationAllowsNormalPermissionBits(t *testing.T) {
	c := restrictedFileContext(http.MethodPost, "/api/v2/files", []byte(`{"path":"/tmp/project/tool","mode":493}`)) // 0755
	if err := validateRestrictedFileOperation(c); err != nil {
		t.Fatalf("normal Unix permission bits should remain allowed: %v", err)
	}
}

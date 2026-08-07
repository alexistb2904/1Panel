package middleware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictedRuntimePathsAllowProjectContent(t *testing.T) {
	root := t.TempDir()
	payload := map[string]any{"codeDir": filepath.Join(root, "app")}
	if err := validateRestrictedRuntimePaths(payload, root); err != nil {
		t.Fatalf("expected project path to be allowed: %v", err)
	}
}

func TestRestrictedRuntimePathsIgnoreNonPathUpdate(t *testing.T) {
	if err := validateRestrictedRuntimePaths(map[string]any{"name": "app", "port": 3000}, ""); err != nil {
		t.Fatalf("non-path update must not require project root: %v", err)
	}
}

func TestRestrictedRuntimePathsRejectEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := validateRestrictedRuntimePaths(map[string]any{"codeDir": outside}, root); err == nil {
		t.Fatal("outside runtime codeDir must be rejected")
	}
}

func TestRestrictedRuntimePathsRejectSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateRestrictedRuntimePaths(map[string]any{"codeDir": link}, root); err == nil {
		t.Fatal("symlink runtime escape must be rejected")
	}
}

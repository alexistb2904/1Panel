package middleware

import (
	"os"
	"path/filepath"
	"testing"
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
	encoded, err := encodeRootsForTest([]string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := decodeRBACRoots(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 0 {
		t.Fatalf("system root must be discarded, got %v", roots)
	}
}

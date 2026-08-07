package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

const headerRBACAllowedRoots = "X-Panel-RBAC-Allowed-Roots"

func FileRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll {
			c.Next()
			return
		}
		mode := c.GetHeader(headerRBACMode)
		if mode != rbacModeIDs && mode != rbacModeNone {
			denyFileAccess(c, "Missing or invalid File Manager RBAC context")
			return
		}
		if err := validateRestrictedFileOperation(c); err != nil {
			denyFileAccess(c, err.Error())
			return
		}
		roots, err := decodeRBACRoots(c.GetHeader(headerRBACAllowedRoots))
		if err != nil || mode == rbacModeNone || len(roots) == 0 {
			denyFileAccess(c, "No project filesystem root is assigned")
			return
		}
		permission := c.GetHeader("X-Panel-RBAC-Permission")
		paths, err := collectRestrictedFilePaths(c)
		if err != nil || len(paths) == 0 {
			denyFileAccess(c, "Unable to resolve File Manager authorization path")
			return
		}
		for _, path := range paths {
			root, resolved, ok := pathWithinAnyProjectRoot(path, roots)
			if !ok {
				denyFileAccess(c, "File path is outside the assigned project roots")
				return
			}
			if permission == "website.files.delete" && resolved == root {
				denyFileAccess(c, "Deleting a project root is not allowed")
				return
			}
		}
		c.Next()
	}
}

func validateRestrictedFileOperation(c *gin.Context) error {
	path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/files")
	switch path {
	case "/owner", "/mode", "/batch/role":
		return errors.New("Changing Unix ownership or permission modes is administrator-only")
	case "/decompress":
		return errors.New("Archive extraction is administrator-only until scoped symlink extraction is enforced")
	}
	if path == "" && c.Request.Method == http.MethodPost {
		body, payload, err := readRBACJSONBody(c)
		if err != nil {
			return errors.New("Unable to validate restricted file creation mode")
		}
		if body != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
		}
		if mode := uintValue(payload["mode"]); mode&07000 != 0 {
			return errors.New("SUID, SGID and sticky permission bits are administrator-only")
		}
	}
	return nil
}

func decodeRBACRoots(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("missing roots")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil { return nil, err }
	var roots []string
	if err := json.Unmarshal(data, &roots); err != nil { return nil, err }
	result := make([]string, 0, len(roots))
	seen := map[string]struct{}{}
	for _, root := range roots {
		if !filepath.IsAbs(root) { continue }
		abs, err := secureCanonicalPath(root)
		if err != nil || abs == string(filepath.Separator) { continue }
		if _, ok := seen[abs]; ok { continue }
		seen[abs] = struct{}{}
		result = append(result, abs)
	}
	return result, nil
}

func collectRestrictedFilePaths(c *gin.Context) ([]string, error) {
	if c.Request.Method == http.MethodGet {
		paths := append([]string{}, c.QueryArray("path")...)
		paths = append(paths, c.QueryArray("paths")...)
		if value := strings.TrimSpace(c.Query("path")); value != "" { paths = append(paths, value) }
		if value := strings.TrimSpace(c.Query("paths")); value != "" {
			var decoded []string
			if json.Unmarshal([]byte(value), &decoded) == nil { paths = append(paths, decoded...) } else { paths = append(paths, strings.Split(value, ",")...) }
		}
		return compactPaths(paths), nil
	}
	contentType := c.GetHeader("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		paths := []string{}
		for _, key := range []string{"path", "dst", "dir", "outputPath"} {
			if value := strings.TrimSpace(c.Request.FormValue(key)); value != "" { paths = append(paths, value) }
		}
		return compactPaths(paths), nil
	}
	body, payload, err := readRBACJSONBody(c)
	if err != nil { return nil, err }
	if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
	paths := []string{}
	appendString := func(key string) { if value := strings.TrimSpace(valueString(payload[key])); value != "" { paths = append(paths, value) } }
	appendStrings := func(key string) { paths = append(paths, valueStrings(payload[key])...) }
	for _, key := range []string{"path", "dst", "oldName", "newPath", "outputPath", "dir", "linkPath"} { appendString(key) }
	for _, key := range []string{"paths", "files", "oldPaths", "coverPaths"} { appendStrings(key) }
	if oldName := strings.TrimSpace(valueString(payload["oldName"])); oldName != "" {
		if newName := strings.TrimSpace(valueString(payload["newName"])); newName != "" {
			if filepath.IsAbs(newName) { paths = append(paths, newName) } else { paths = append(paths, filepath.Join(filepath.Dir(oldName), newName)) }
		}
	}
	if dst := strings.TrimSpace(valueString(payload["dst"])); dst != "" {
		if name := strings.TrimSpace(valueString(payload["name"])); name != "" { paths = append(paths, filepath.Join(dst, name)) }
	}
	if path := strings.TrimSpace(valueString(payload["path"])); path != "" {
		if name := strings.TrimSpace(valueString(payload["name"])); name != "" && (strings.HasSuffix(c.Request.URL.Path, "/wget") || strings.HasSuffix(c.Request.URL.Path, "/chunkdownload")) { paths = append(paths, filepath.Join(path, name)) }
	}
	if rawFiles, ok := payload["files"].([]any); ok {
		for _, raw := range rawFiles {
			item, ok := raw.(map[string]any)
			if !ok { continue }
			base := strings.TrimSpace(valueString(item["path"]))
			if base != "" { paths = append(paths, base) }
			input := strings.TrimSpace(valueString(item["inputFile"]))
			if input != "" {
				if filepath.IsAbs(input) || base == "" { paths = append(paths, input) } else { paths = append(paths, filepath.Join(base, input)) }
			}
		}
	}
	return compactPaths(paths), nil
}

func compactPaths(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" { continue }
		if _, ok := seen[value]; ok { continue }
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func pathWithinAnyProjectRoot(target string, roots []string) (string, string, bool) {
	if !filepath.IsAbs(target) { return "", "", false }
	resolved, err := secureCanonicalPath(target)
	if err != nil { return "", "", false }
	for _, root := range roots {
		rel, err := filepath.Rel(root, resolved)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) { return root, resolved, true }
	}
	return "", resolved, false
}

// secureCanonicalPath resolves symlinks for the longest existing parent. This
// also protects create/upload destinations that do not exist yet but whose
// parent is a symlink escaping the project root.
func secureCanonicalPath(target string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(target))
	if err != nil { return "", err }
	probe := abs
	suffix := []string{}
	for {
		if _, statErr := os.Lstat(probe); statErr == nil {
			resolved, err := filepath.EvalSymlinks(probe)
			if err != nil { return "", err }
			for i := len(suffix) - 1; i >= 0; i-- { resolved = filepath.Join(resolved, suffix[i]) }
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(probe)
		if parent == probe { return abs, nil }
		suffix = append(suffix, filepath.Base(probe))
		probe = parent
	}
}

func denyFileAccess(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"code": http.StatusForbidden, "message": message})
	c.Abort()
}

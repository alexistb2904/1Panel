package middleware

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/dto/request"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/gin-gonic/gin"
)

const headerRBACProjectRoot = "X-Panel-RBAC-Project-Root"

func RuntimeRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll {
			c.Next()
			return
		}
		mode := c.GetHeader(headerRBACMode)
		if mode != rbacModeIDs && mode != rbacModeNone {
			denyRuntimeAccess(c, "Missing or invalid runtime RBAC context")
			return
		}
		allowed := parseRBACStringIDs(c.GetHeader(headerRBACResourceIDs))
		if mode == rbacModeNone { allowed = nil }
		if c.Request.URL.Path == "/api/v2/runtimes/search" && c.Request.Method == http.MethodPost {
			var req request.RuntimeSearch
			if err := helper.CheckBindAndValidate(&req, c); err != nil { return }
			total, items, err := service.PageRuntimesForRBAC(req, allowed)
			if err != nil { helper.InternalServer(c, err); return }
			helper.SuccessWithData(c, dto.PageResult{Total: total, Items: items})
			return
		}

		body, payload, err := readRBACJSONBody(c)
		if err != nil { denyRuntimeAccess(c, "Unable to parse runtime authorization target"); return }
		if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
		key, creating, ok, err := runtimeKeyForRequest(c.Request.Method, c.Request.URL.Path, payload)
		if err != nil || !ok || key == "" { denyRuntimeAccess(c, "Runtime operation is not available to restricted identities"); return }
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, item := range allowed { allowedSet[item] = struct{}{} }
		if _, exists := allowedSet[key]; !exists {
			if id := runtimeIDFromPayloadOrPath(c.Request.URL.Path, payload); id != 0 {
				if _, numericExists := allowedSet[strconv.FormatUint(uint64(id), 10)]; !numericExists { denyRuntimeAccess(c, "Runtime is outside the assigned project scope"); return }
			} else { denyRuntimeAccess(c, "Runtime is outside the assigned project scope"); return }
		}
		if creating || c.Request.URL.Path == "/api/v2/runtimes/update" || c.Request.URL.Path == "/api/v2/runtimes/php/container/update" {
			if err := validateRestrictedRuntimePaths(payload, c.GetHeader(headerRBACProjectRoot)); err != nil { denyRuntimeAccess(c, err.Error()); return }
		}
		c.Next()
	}
}

func runtimeKeyForRequest(method, path string, payload map[string]any) (string, bool, bool, error) {
	if path == "/api/v2/runtimes" && method == http.MethodPost {
		name := strings.TrimSpace(valueString(payload["name"]))
		return service.RuntimeResourceKey(name), true, name != "", nil
	}
	id := runtimeIDFromPayloadOrPath(path, payload)
	if id == 0 { return "", false, false, nil }
	key, err := service.RuntimeKeyForID(id)
	return key, false, err == nil, err
}

func runtimeIDFromPayloadOrPath(path string, payload map[string]any) uint {
	for _, key := range []string{"id", "ID", "runtimeID", "runtimeId"} {
		if id := uintValue(payload[key]); id != 0 { return id }
	}
	relative := strings.Trim(strings.TrimPrefix(path, "/api/v2/runtimes"), "/")
	parts := strings.Split(relative, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if id, err := strconv.ParseUint(parts[i], 10, 64); err == nil && id > 0 { return uint(id) }
	}
	return 0
}

func validateRestrictedRuntimePaths(payload map[string]any, projectRoot string) error {
	codeDir := strings.TrimSpace(valueString(payload["codeDir"]))
	rawVolumes, hasVolumes := payload["volumes"].([]any)
	hasHostPathMutation := codeDir != "" || (hasVolumes && len(rawVolumes) > 0)
	if !hasHostPathMutation { return nil }
	projectRoot = strings.TrimSpace(projectRoot)
	if projectRoot == "" { return &runtimePolicyError{"Project root is required for restricted runtime host path changes"} }
	root, err := secureCanonicalPath(projectRoot)
	if err != nil || root == string(filepath.Separator) { return &runtimePolicyError{"Invalid project root"} }
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() { return &runtimePolicyError{"Project root must exist and be a directory"} }
	if codeDir != "" {
		if err := ensurePathInsideRuntimeRoot(root, codeDir); err != nil { return err }
	}
	if hasVolumes {
		for _, raw := range rawVolumes {
			volume, ok := raw.(map[string]any)
			if !ok { return &runtimePolicyError{"Invalid runtime volume definition"} }
			source := strings.TrimSpace(valueString(volume["source"]))
			if source == "" { continue }
			if err := ensurePathInsideRuntimeRoot(root, source); err != nil { return err }
		}
	}
	return nil
}

type runtimePolicyError struct{ message string }
func (e *runtimePolicyError) Error() string { return e.message }

func ensurePathInsideRuntimeRoot(root, target string) error {
	if !filepath.IsAbs(target) { target = filepath.Join(root, target) }
	resolved, err := secureCanonicalPath(target)
	if err != nil { return &runtimePolicyError{"Invalid runtime host path"} }
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return &runtimePolicyError{"Runtime host paths must stay inside the assigned project root"}
	}
	return nil
}

func denyRuntimeAccess(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"code": http.StatusForbidden, "message": message})
	c.Abort()
}

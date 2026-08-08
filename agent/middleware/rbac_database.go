package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/gin-gonic/gin"
)

// DatabaseRBAC scopes logical databases (schemas/databases created inside a
// configured MySQL/PostgreSQL/MongoDB instance). Administration of the backing
// database server itself is intentionally not part of this middleware and is
// default-denied by Core for restricted identities.
func DatabaseRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll { c.Next(); return }
		mode := c.GetHeader(headerRBACMode)
		if mode != rbacModeIDs && mode != rbacModeNone { denyDatabaseAccess(c, "Missing or invalid database RBAC context"); return }
		allowed := parseRBACStringIDs(c.GetHeader(headerRBACResourceIDs))
		if mode == rbacModeNone { allowed = nil }
		if handleRestrictedDatabaseCollection(c, allowed) { return }

		body, payload, err := readRBACJSONBody(c)
		if err != nil { denyDatabaseAccess(c, "Unable to resolve database authorization target"); return }
		if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
		keys, ok, err := databaseKeysForRequest(c.Request.URL.Path, payload)
		if err != nil || !ok || len(keys) == 0 { denyDatabaseAccess(c, "Database operation is not available to restricted identities"); return }
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, key := range allowed { allowedSet[key] = struct{}{} }
		for _, key := range keys {
			if _, exists := allowedSet[key]; !exists { denyDatabaseAccess(c, "Database is outside the assigned project scope"); return }
		}
		c.Next()
	}
}

func handleRestrictedDatabaseCollection(c *gin.Context, allowed []string) bool {
	switch c.Request.URL.Path {
	case "/api/v2/databases/search":
		var req dto.MysqlDBSearch
		if err := helper.CheckBindAndValidate(&req, c); err != nil { return true }
		total, items, err := service.SearchMysqlForRBAC(req, allowed)
		if err != nil { helper.InternalServer(c, err); return true }
		helper.SuccessWithData(c, dto.PageResult{Total: total, Items: items})
		return true
	case "/api/v2/databases/pg/search":
		var req dto.PostgresqlDBSearch
		if err := helper.CheckBindAndValidate(&req, c); err != nil { return true }
		total, items, err := service.SearchPostgresqlForRBAC(req, allowed)
		if err != nil { helper.InternalServer(c, err); return true }
		helper.SuccessWithData(c, dto.PageResult{Total: total, Items: items})
		return true
	case "/api/v2/databases/mongodb/search":
		var req dto.MongodbDBSearch
		if err := helper.CheckBindAndValidate(&req, c); err != nil { return true }
		total, items, err := service.SearchMongodbForRBAC(req, allowed)
		if err != nil { helper.InternalServer(c, err); return true }
		helper.SuccessWithData(c, dto.PageResult{Total: total, Items: items})
		return true
	default:
		return false
	}
}

func databaseKeysForRequest(path string, payload map[string]any) ([]string, bool, error) {
	value := func(key string) string { return strings.TrimSpace(valueString(payload[key])) }
	id := uintValue(payload["id"])
	instance := value("database")
	name := value("name")

	switch path {
	case "/api/v2/databases":
		if instance == "" || name == "" { return nil, false, nil }
		return []string{service.DatabaseResourceKey("mysql", instance, name)}, true, nil
	case "/api/v2/databases/pg":
		if instance == "" || name == "" { return nil, false, nil }
		return []string{service.DatabaseResourceKey("postgresql", instance, name)}, true, nil
	case "/api/v2/databases/mongodb":
		if instance == "" || name == "" { return nil, false, nil }
		return []string{service.DatabaseResourceKey("mongodb", instance, name)}, true, nil
	case "/api/v2/databases/del", "/api/v2/databases/del/check", "/api/v2/databases/description/update", "/api/v2/databases/change/password", "/api/v2/databases/change/access":
		if id == 0 { return nil, false, nil }
		kind := value("type")
		if kind == "" { kind = "mysql" }
		key, err := service.ResolveDatabaseResourceKeyByID(kind, id)
		return []string{key}, err == nil, err
	case "/api/v2/databases/pg/del", "/api/v2/databases/pg/del/check", "/api/v2/databases/pg/description", "/api/v2/databases/pg/password", "/api/v2/databases/pg/bind", "/api/v2/databases/pg/privileges":
		if id != 0 { key, err := service.ResolveDatabaseResourceKeyByID("postgresql", id); return []string{key}, err == nil, err }
		if instance != "" && name != "" { return []string{service.DatabaseResourceKey("postgresql", instance, name)}, true, nil }
		return nil, false, nil
	case "/api/v2/databases/mongodb/del", "/api/v2/databases/mongodb/del/check", "/api/v2/databases/mongodb/description", "/api/v2/databases/mongodb/password", "/api/v2/databases/mongodb/bind", "/api/v2/databases/mongodb/privileges", "/api/v2/databases/mongodb/privileges/change":
		if id != 0 { key, err := service.ResolveDatabaseResourceKeyByID("mongodb", id); return []string{key}, err == nil, err }
		if instance != "" && name != "" { return []string{service.DatabaseResourceKey("mongodb", instance, name)}, true, nil }
		return nil, false, nil
	case "/api/v2/databases/grants", "/api/v2/databases/grants/del":
		target := value("db")
		if instance == "" || target == "" { return nil, false, nil }
		return []string{service.DatabaseResourceKey("mysql", instance, target)}, true, nil
	case "/api/v2/databases/users":
		dbs := valueStrings(payload["dbs"])
		if instance == "" || len(dbs) == 0 { return nil, false, nil }
		keys := make([]string, 0, len(dbs))
		for _, db := range dbs { keys = append(keys, service.DatabaseResourceKey("mysql", instance, db)) }
		return keys, true, nil
	}
	return nil, false, nil
}

func readRBACJSONBody(c *gin.Context) ([]byte, map[string]any, error) {
	if c.Request.Body == nil { return nil, map[string]any{}, nil }
	body, err := io.ReadAll(c.Request.Body)
	if err != nil { return nil, nil, err }
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 || strings.HasPrefix(c.GetHeader("Content-Type"), "multipart/form-data") { return body, map[string]any{}, nil }
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	payload := map[string]any{}
	if err := decoder.Decode(&payload); err != nil { return body, nil, err }
	return body, payload, nil
}

// parseRBACStringIDs accepts the structured b64 JSON transport emitted by new
// Core builds. The CSV branch is retained only for rolling-upgrade compatibility
// with an older Core; new requests never rely on delimiter-sensitive encoding.
func parseRBACStringIDs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "b64:") {
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, "b64:"))
		if err != nil { return nil }
		var values []string
		if err := json.Unmarshal(decoded, &values); err != nil { return nil }
		return uniqueRBACStrings(values)
	}
	return uniqueRBACStrings(strings.Split(raw, ","))
}

func uniqueRBACStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, part := range values {
		part = strings.TrimSpace(part)
		if part == "" { continue }
		if _, ok := seen[part]; ok { continue }
		seen[part] = struct{}{}
		result = append(result, part)
	}
	return result
}

func denyDatabaseAccess(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"code": http.StatusForbidden, "message": message})
	c.Abort()
}

package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/dto/request"
	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/gin-gonic/gin"
)

const (
	headerRBACMode        = "X-Panel-RBAC-Mode"
	headerRBACResourceIDs = "X-Panel-RBAC-Resource-IDs"
	headerInternalRequest = "X-Panel-Internal-Request"

	rbacModeAll  = "all"
	rbacModeIDs  = "ids"
	rbacModeNone = "none"
)

// WebsiteRBAC enforces the resource scope calculated by Core. Direct trusted
// Core-to-Agent calls are explicitly marked as internal; browser traffic is
// never allowed to fall back to an unscoped website handler.
func WebsiteRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerInternalRequest) == "1" {
			c.Next()
			return
		}

		mode := c.GetHeader(headerRBACMode)
		if mode == "" {
			denyWebsiteAccess(c, "Missing RBAC context")
			return
		}
		if mode == rbacModeAll {
			c.Next()
			return
		}

		allowedIDs, ok := parseAllowedWebsiteIDs(c.GetHeader(headerRBACResourceIDs))
		if mode == rbacModeNone {
			allowedIDs = []uint{}
			ok = true
		}
		if mode != rbacModeIDs && mode != rbacModeNone {
			denyWebsiteAccess(c, "Invalid RBAC context")
			return
		}
		if !ok {
			denyWebsiteAccess(c, "Invalid website scope")
			return
		}

		if handleRestrictedWebsiteCollection(c, allowedIDs) {
			return
		}
		if len(allowedIDs) == 0 {
			denyWebsiteAccess(c, "Website access denied")
			return
		}

		targetIDs, err := resolveWebsiteIDs(c)
		if err != nil || len(targetIDs) == 0 {
			denyWebsiteAccess(c, "Unable to resolve website authorization target")
			return
		}
		allowed := make(map[uint]struct{}, len(allowedIDs))
		for _, id := range allowedIDs {
			allowed[id] = struct{}{}
		}
		for _, id := range targetIDs {
			if _, exists := allowed[id]; !exists {
				denyWebsiteAccess(c, "Website access denied")
				return
			}
		}
		c.Next()
	}
}

func handleRestrictedWebsiteCollection(c *gin.Context, allowedIDs []uint) bool {
	path := c.Request.URL.Path
	switch {
	case path == "/api/v2/websites/search" && c.Request.Method == http.MethodPost:
		var req request.WebsiteSearch
		if err := helper.CheckBindAndValidate(&req, c); err != nil {
			return true
		}
		total, websites, err := service.PageWebsitesForRBAC(req, allowedIDs)
		if err != nil {
			helper.InternalServer(c, err)
			return true
		}
		helper.SuccessWithData(c, dto.PageResult{Total: total, Items: websites})
		return true
	case path == "/api/v2/websites/list" && c.Request.Method == http.MethodGet:
		websites, err := service.GetWebsitesForRBAC(allowedIDs)
		if err != nil {
			helper.InternalServer(c, err)
			return true
		}
		helper.SuccessWithData(c, websites)
		return true
	case path == "/api/v2/websites/options" && c.Request.Method == http.MethodPost:
		var req request.WebsiteOptionReq
		if err := helper.CheckBindAndValidate(&req, c); err != nil {
			return true
		}
		websites, err := service.GetWebsiteOptionsForRBAC(req, allowedIDs)
		if err != nil {
			helper.InternalServer(c, err)
			return true
		}
		helper.SuccessWithData(c, websites)
		return true
	default:
		return false
	}
}

func resolveWebsiteIDs(c *gin.Context) ([]uint, error) {
	if ids := websiteIDsFromPath(c.Request.URL.Path); len(ids) > 0 {
		return ids, nil
	}
	if c.Request.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	// Domain update/delete requests carry a domain record ID rather than a
	// website ID. Resolve the owning website before authorization.
	if c.Request.URL.Path == "/api/v2/websites/domains/del" || c.Request.URL.Path == "/api/v2/websites/domains/update" {
		domainID := uintValue(payload["id"])
		if domainID == 0 {
			return nil, nil
		}
		var domain model.WebsiteDomain
		if err := global.DB.Select("id", "website_id").First(&domain, domainID).Error; err != nil {
			return nil, err
		}
		return []uint{domain.WebsiteID}, nil
	}

	for _, key := range []string{"websiteID", "websiteId", "website_id"} {
		if id := uintValue(payload[key]); id != 0 {
			return []uint{id}, nil
		}
	}
	if raw, exists := payload["ids"]; exists {
		ids := uintSlice(raw)
		if len(ids) > 0 {
			return ids, nil
		}
	}
	if id := uintValue(payload["id"]); id != 0 {
		return []uint{id}, nil
	}
	return nil, nil
}

func websiteIDsFromPath(path string) []uint {
	relative := strings.Trim(strings.TrimPrefix(path, "/api/v2/websites"), "/")
	if relative == "" {
		return nil
	}
	parts := strings.Split(relative, "/")
	if id := parseUint(parts[0]); id != 0 {
		return []uint{id}
	}
	if len(parts) >= 2 {
		switch parts[0] {
		case "domains", "cors", "resource":
			if id := parseUint(parts[1]); id != 0 {
				return []uint{id}
			}
		}
	}
	if len(parts) >= 3 && (parts[0] == "realip" || parts[0] == "proxy") && parts[1] == "config" {
		if id := parseUint(parts[2]); id != 0 {
			return []uint{id}
		}
	}
	return nil
}

func parseAllowedWebsiteIDs(raw string) ([]uint, bool) {
	if raw == "" {
		return []uint{}, true
	}
	parts := strings.Split(raw, ",")
	ids := make([]uint, 0, len(parts))
	seen := make(map[uint]struct{}, len(parts))
	for _, part := range parts {
		id := parseUint(strings.TrimSpace(part))
		if id == 0 {
			return nil, false
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, true
}

func uintSlice(raw any) []uint {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	ids := make([]uint, 0, len(items))
	for _, item := range items {
		if id := uintValue(item); id != 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

func uintValue(raw any) uint {
	switch value := raw.(type) {
	case json.Number:
		parsed, _ := strconv.ParseUint(value.String(), 10, 64)
		return uint(parsed)
	case float64:
		if value > 0 {
			return uint(value)
		}
	case string:
		return parseUint(value)
	}
	return 0
}

func parseUint(raw string) uint {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 {
		return 0
	}
	return uint(value)
}

func denyWebsiteAccess(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"code": http.StatusForbidden, "message": message})
	c.Abort()
}

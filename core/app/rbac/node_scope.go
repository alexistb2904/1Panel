package rbac

import (
	"errors"
	"net/url"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func normalizeNodeSelector(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "undefined" {
		return "", nil
	}
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return "", errors.New("node selector is not valid URL-encoded data")
	}
	value = strings.TrimSpace(decoded)
	if value == "" || value == "undefined" {
		return "", nil
	}
	if value == "0" || strings.EqualFold(value, "local") || strings.EqualFold(value, "master") {
		return "local", nil
	}
	return value, nil
}

// ResolveRequestNodeSelector is the single source of truth used by both RBAC
// authorization and the Core proxy. Supplying contradictory selectors is
// rejected instead of authorizing against one node and executing on another.
func ResolveRequestNodeSelector(c *gin.Context) (string, error) {
	raw := []string{c.Query("operateNode"), c.GetHeader("CurrentNode"), c.GetHeader("X-Panel-Current-Node")}
	selected := ""
	for _, value := range raw {
		normalized, err := normalizeNodeSelector(value)
		if err != nil {
			return "", err
		}
		if normalized == "" {
			continue
		}
		if selected == "" {
			selected = normalized
			continue
		}
		if selected != normalized {
			return "", errors.New("conflicting node selectors are not allowed")
		}
	}
	if selected == "" {
		return "local", nil
	}
	return selected, nil
}

// ResolveRequestNodeID maps the canonical request-node selector to a stable
// RBAC node ID. Local/master is always 0. Remote selectors must be explicitly
// registered by an administrator before scoped identities may use them.
func ResolveRequestNodeID(c *gin.Context) (uint, string, error) {
	selector, err := ResolveRequestNodeSelector(c)
	if err != nil {
		return 0, "", err
	}
	if selector == "local" {
		return 0, selector, nil
	}
	var node model.AccessNodeScope
	err = global.DB.Where("external_key = ? AND status = ?", selector, model.AccessUserStatusActive).First(&node).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, selector, errors.New("remote node is not registered in RBAC")
		}
		return 0, selector, err
	}
	return node.ID, selector, nil
}

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

func requestNodeSelector(c *gin.Context) string {
	for _, value := range []string{c.Query("operateNode"), c.GetHeader("CurrentNode"), c.GetHeader("X-Panel-Current-Node")} {
		value = strings.TrimSpace(value)
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = strings.TrimSpace(decoded)
		}
		if value != "" && value != "undefined" {
			return value
		}
	}
	return "local"
}

// ResolveRequestNodeID maps the provider's opaque current-node selector to a
// stable RBAC node ID. Local/master is always 0. Remote selectors must be
// explicitly registered by an administrator before scoped identities may use
// them.
func ResolveRequestNodeID(c *gin.Context) (uint, string, error) {
	selector := requestNodeSelector(c)
	if selector == "local" || selector == "0" || selector == "master" {
		return 0, selector, nil
	}
	var node model.AccessNodeScope
	err := global.DB.Where("external_key = ? AND status = ?", selector, "active").First(&node).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, selector, errors.New("remote node is not registered in RBAC")
		}
		return 0, selector, err
	}
	return node.ID, selector, nil
}

package v2

import (
	"net/http"

	"github.com/1Panel-dev/1Panel/core/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/app/service"
	"github.com/gin-gonic/gin"
)

func (b *BaseApi) ListMyAccessProjects(c *gin.Context) {
	userID, ok := rbac.CurrentUserID(c)
	if !ok {
		helper.ErrorWithDetail(c, http.StatusUnauthorized, "ErrAuth", nil)
		return
	}
	items, err := service.ListMyAccessProjects(userID)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, items)
}

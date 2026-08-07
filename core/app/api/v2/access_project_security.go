package v2

import (
	"github.com/1Panel-dev/1Panel/core/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/service"
	"github.com/gin-gonic/gin"
)

func (b *BaseApi) ListAccessProjectSecurity(c *gin.Context) {
	items, err := service.ListAccessProjectSecurity()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, items)
}

func (b *BaseApi) UpdateAccessProjectRoot(c *gin.Context) {
	var req dto.AccessProjectRootUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := service.UpdateAccessProjectRoot(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

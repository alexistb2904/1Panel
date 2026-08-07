package v2

import (
	"strconv"

	"github.com/1Panel-dev/1Panel/core/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
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
	enabled := true
	if req.Enabled != nil { enabled = *req.Enabled }
	rbac.AuditMutation(c, "rbac.project.node_boundary.update", "project", strconv.FormatUint(uint64(req.ID), 10), map[string]any{"nodeId": req.NodeID, "rootPath": req.RootPath, "enabled": enabled})
	helper.Success(c)
}

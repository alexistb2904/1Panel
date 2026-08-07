package v2

import (
	"github.com/1Panel-dev/1Panel/core/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/gin-gonic/gin"
)

func (b *BaseApi) ListAccessUsers(c *gin.Context) {
	items, err := accessService.ListUsers()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, items)
}

func (b *BaseApi) CreateAccessUser(c *gin.Context) {
	var req dto.AccessUserCreate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := accessService.CreateUser(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

func (b *BaseApi) UpdateAccessUser(c *gin.Context) {
	var req dto.AccessUserUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := accessService.UpdateUser(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

func (b *BaseApi) UpdateAccessUserStatus(c *gin.Context) {
	var req dto.AccessUserStatusUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := accessService.UpdateUserStatus(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

func (b *BaseApi) ResetAccessUserPassword(c *gin.Context) {
	var req dto.AccessUserPasswordReset
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := accessService.ResetUserPassword(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

func (b *BaseApi) ReplaceAccessUserBindings(c *gin.Context) {
	var req dto.AccessUserBindingsUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := accessService.ReplaceUserBindings(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

func (b *BaseApi) ListAccessRoles(c *gin.Context) {
	items, err := accessService.ListRoles()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, items)
}

func (b *BaseApi) ListAccessProjects(c *gin.Context) {
	items, err := accessService.ListProjects()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, items)
}

func (b *BaseApi) CreateAccessProject(c *gin.Context) {
	var req dto.AccessProjectCreate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := accessService.CreateProject(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

func (b *BaseApi) UpdateAccessProject(c *gin.Context) {
	var req dto.AccessProjectUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := accessService.UpdateProject(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

func (b *BaseApi) ReplaceAccessProjectResources(c *gin.Context) {
	var req dto.AccessProjectResourcesUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := accessService.ReplaceProjectResources(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

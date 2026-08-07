package v2

import (
	"strconv"

	"github.com/1Panel-dev/1Panel/core/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/gin-gonic/gin"
)

func (b *BaseApi) ListAccessNodes(c *gin.Context) {
	items, err := accessService.ListNodes()
	if err != nil { helper.InternalServer(c, err); return }
	helper.SuccessWithData(c, items)
}

func (b *BaseApi) CreateAccessNode(c *gin.Context) {
	var req dto.AccessNodeCreate
	if err := helper.CheckBindAndValidate(&req, c); err != nil { return }
	if err := accessService.CreateNode(req); err != nil { helper.BadRequest(c, err); return }
	rbac.AuditMutation(c, "rbac.node.create", "node", req.ExternalKey, map[string]any{"name": req.Name})
	helper.Success(c)
}

func (b *BaseApi) UpdateAccessNode(c *gin.Context) {
	var req dto.AccessNodeUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil { return }
	if err := accessService.UpdateNode(req); err != nil { helper.BadRequest(c, err); return }
	rbac.AuditMutation(c, "rbac.node.update", "node", strconv.FormatUint(uint64(req.ID), 10), map[string]any{"externalKey": req.ExternalKey, "status": req.Status})
	helper.Success(c)
}

func (b *BaseApi) ListAccessServiceAccounts(c *gin.Context) {
	items, err := accessService.ListServiceAccounts()
	if err != nil { helper.InternalServer(c, err); return }
	helper.SuccessWithData(c, items)
}

func (b *BaseApi) CreateAccessServiceAccount(c *gin.Context) {
	var req dto.AccessServiceAccountCreate
	if err := helper.CheckBindAndValidate(&req, c); err != nil { return }
	token, err := accessService.CreateServiceAccount(req)
	if err != nil { helper.BadRequest(c, err); return }
	rbac.AuditMutation(c, "rbac.service_account.create", "service_account", strconv.FormatUint(uint64(token.ID), 10), map[string]any{"name": req.Name, "keyId": token.KeyID})
	helper.SuccessWithData(c, token)
}

func (b *BaseApi) UpdateAccessServiceAccount(c *gin.Context) {
	var req dto.AccessServiceAccountUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil { return }
	if err := accessService.UpdateServiceAccount(req); err != nil { helper.BadRequest(c, err); return }
	rbac.AuditMutation(c, "rbac.service_account.update", "service_account", strconv.FormatUint(uint64(req.ID), 10), map[string]any{"name": req.Name, "status": req.Status})
	helper.Success(c)
}

func (b *BaseApi) RotateAccessServiceAccount(c *gin.Context) {
	var req dto.AccessServiceAccountRotate
	if err := helper.CheckBindAndValidate(&req, c); err != nil { return }
	token, err := accessService.RotateServiceAccount(req)
	if err != nil { helper.BadRequest(c, err); return }
	rbac.AuditMutation(c, "rbac.service_account.rotate", "service_account", strconv.FormatUint(uint64(req.ID), 10), map[string]any{"keyId": token.KeyID})
	helper.SuccessWithData(c, token)
}

func (b *BaseApi) SearchAccessAudit(c *gin.Context) {
	var req dto.AccessAuditSearch
	if err := helper.CheckBindAndValidate(&req, c); err != nil { return }
	total, items, err := accessService.SearchAudit(req)
	if err != nil { helper.InternalServer(c, err); return }
	helper.SuccessWithData(c, dto.PageResult{Total: total, Items: items})
}

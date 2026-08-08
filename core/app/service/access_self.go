package service

import (
	"strconv"

	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/global"
)

// ListMyAccessProjects returns only active projects the current user can
// actually use. Global viewers (Administrator/Security Advisor) receive all
// active projects; normal staff receive project-scoped bindings only. Host root
// paths stay hidden and pending ownership reservations are never presented as
// usable resources because Evaluator intentionally excludes them as grants.
func ListMyAccessProjects(userID uint) ([]dto.AccessProjectInfo, error) {
	evaluator := rbac.NewEvaluator(global.DB)
	globalAccess, err := evaluator.CanGlobal(userID, "project.view")
	if err != nil { return nil, err }

	query := global.DB.Model(&model.AccessProject{}).Where("status = ?", "active").Order("name ASC")
	if !globalAccess {
		var scopeIDs []string
		if err := global.DB.Table("rbac_role_bindings AS b").
			Distinct("b.scope_id").
			Joins("JOIN rbac_role_permissions rp ON rp.role_id = b.role_id").
			Joins("JOIN rbac_permissions p ON p.id = rp.permission_id").
			Where("b.user_id = ? AND b.scope_type = ? AND p.code = ?", userID, model.AccessScopeProject, "project.view").
			Pluck("b.scope_id", &scopeIDs).Error; err != nil { return nil, err }
		projectIDs := make([]uint, 0, len(scopeIDs))
		for _, scopeID := range scopeIDs {
			parsed, err := strconv.ParseUint(scopeID, 10, 64)
			if err == nil && parsed != 0 { projectIDs = append(projectIDs, uint(parsed)) }
		}
		if len(projectIDs) == 0 { return []dto.AccessProjectInfo{}, nil }
		query = query.Where("id IN ?", projectIDs)
	}

	var projects []model.AccessProject
	if err := query.Find(&projects).Error; err != nil { return nil, err }
	result := make([]dto.AccessProjectInfo, 0, len(projects))
	for _, project := range projects {
		item := dto.AccessProjectInfo{
			ID: project.ID, Name: project.Name, Slug: project.Slug,
			Description: project.Description, Status: project.Status, CreatedAt: project.CreatedAt,
		}
		nodes, err := loadAccessProjectNodeInfos(global.DB, project.ID, false)
		if err != nil { return nil, err }
		item.Nodes = nodes
		var resources []model.AccessProjectResource
		if err := global.DB.Where("project_id = ? AND state = ?", project.ID, model.AccessResourceStateActive).
			Order("node_id ASC, resource_type ASC, resource_id ASC").Find(&resources).Error; err != nil { return nil, err }
		for _, resource := range resources {
			item.Resources = append(item.Resources, dto.AccessProjectResourceInput{
				NodeID: resource.NodeID, ResourceType: resource.ResourceType, ResourceID: resource.ResourceID,
			})
		}
		result = append(result, item)
	}
	return result, nil
}

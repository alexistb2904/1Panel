package rbac

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"gorm.io/gorm"
)

type ResourceContext struct {
	NodeID    uint
	ProjectID uint
	Type      string
	ID        string
}

type ResourceFilter struct {
	All bool
	IDs []string
}

type Evaluator struct {
	db *gorm.DB
}

func NewEvaluator(db *gorm.DB) *Evaluator {
	return &Evaluator{db: db}
}

// Can evaluates one permission against one concrete authorization context.
// Authorization is additive and default-deny: a request is allowed only when
// at least one binding carrying the permission covers the requested scope.
func (e *Evaluator) Can(userID uint, permissionCode string, resource ResourceContext) (bool, error) {
	active, err := e.isActiveUser(userID)
	if err != nil || !active {
		return false, err
	}

	admin, err := e.isGlobalAdministrator(userID)
	if err != nil || admin {
		return admin, err
	}

	bindings, err := e.bindingsForPermission(userID, permissionCode)
	if err != nil {
		return false, err
	}
	for _, binding := range bindings {
		match, err := e.bindingMatches(binding, resource)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// PermissionCodes returns the union of capabilities a user may exercise on at
// least one scope. It is suitable for frontend navigation hints, but concrete
// resource actions must still call Can server-side.
func (e *Evaluator) PermissionCodes(userID uint) ([]string, error) {
	active, err := e.isActiveUser(userID)
	if err != nil || !active {
		return []string{}, err
	}
	admin, err := e.isGlobalAdministrator(userID)
	if err != nil {
		return nil, err
	}
	if admin {
		return AllPermissionCodes(), nil
	}

	var codes []string
	err = e.db.Table("rbac_permissions AS p").
		Distinct("p.code").
		Joins("JOIN rbac_role_permissions rp ON rp.permission_id = p.id").
		Joins("JOIN rbac_role_bindings rb ON rb.role_id = rp.role_id").
		Where("rb.user_id = ?", userID).
		Order("p.code ASC").
		Pluck("p.code", &codes).Error
	if err != nil {
		return nil, fmt.Errorf("resolve user permission codes: %w", err)
	}
	return codes, nil
}

// AccessibleResourceIDs builds a server-side filter for list endpoints. All is
// true only when a global/node binding legitimately covers every resource of
// the requested type. Otherwise IDs contains explicit and project-derived IDs.
func (e *Evaluator) AccessibleResourceIDs(userID uint, permissionCode, resourceType string, nodeID uint) (ResourceFilter, error) {
	active, err := e.isActiveUser(userID)
	if err != nil || !active {
		return ResourceFilter{}, err
	}
	admin, err := e.isGlobalAdministrator(userID)
	if err != nil {
		return ResourceFilter{}, err
	}
	if admin {
		return ResourceFilter{All: true}, nil
	}

	bindings, err := e.bindingsForPermission(userID, permissionCode)
	if err != nil {
		return ResourceFilter{}, err
	}
	ids := make(map[string]struct{})
	for _, binding := range bindings {
		switch binding.ScopeType {
		case model.AccessScopeGlobal:
			return ResourceFilter{All: true}, nil
		case model.AccessScopeNode:
			if nodeID != 0 && binding.ScopeID == strconv.FormatUint(uint64(nodeID), 10) {
				return ResourceFilter{All: true}, nil
			}
		case model.AccessScopeResource:
			if binding.ResourceType == resourceType {
				ids[binding.ScopeID] = struct{}{}
			}
		case model.AccessScopeProject:
			projectID, err := strconv.ParseUint(binding.ScopeID, 10, 64)
			if err != nil {
				continue
			}
			query := e.db.Model(&model.AccessProjectResource{}).
				Where("project_id = ? AND resource_type = ?", uint(projectID), resourceType)
			if nodeID != 0 {
				query = query.Where("node_id = ?", nodeID)
			}
			var projectIDs []string
			if err := query.Pluck("resource_id", &projectIDs).Error; err != nil {
				return ResourceFilter{}, fmt.Errorf("resolve project resources: %w", err)
			}
			for _, id := range projectIDs {
				ids[id] = struct{}{}
			}
		}
	}

	result := ResourceFilter{IDs: make([]string, 0, len(ids))}
	for id := range ids {
		result.IDs = append(result.IDs, id)
	}
	return result, nil
}

func (e *Evaluator) bindingsForPermission(userID uint, permissionCode string) ([]model.AccessRoleBinding, error) {
	var bindings []model.AccessRoleBinding
	err := e.db.Table("rbac_role_bindings AS rb").
		Select("rb.*").
		Joins("JOIN rbac_role_permissions rp ON rp.role_id = rb.role_id").
		Joins("JOIN rbac_permissions p ON p.id = rp.permission_id").
		Where("rb.user_id = ? AND p.code = ?", userID, permissionCode).
		Find(&bindings).Error
	if err != nil {
		return nil, fmt.Errorf("resolve permission bindings: %w", err)
	}
	return bindings, nil
}

func (e *Evaluator) bindingMatches(binding model.AccessRoleBinding, resource ResourceContext) (bool, error) {
	switch binding.ScopeType {
	case model.AccessScopeGlobal:
		return true, nil
	case model.AccessScopeNode:
		return resource.NodeID != 0 && binding.ScopeID == strconv.FormatUint(uint64(resource.NodeID), 10), nil
	case model.AccessScopeResource:
		return resource.Type != "" && resource.ID != "" && binding.ResourceType == resource.Type && binding.ScopeID == resource.ID, nil
	case model.AccessScopeProject:
		if resource.Type == "project" && resource.ID == binding.ScopeID {
			return true, nil
		}
		if resource.ProjectID != 0 {
			return binding.ScopeID == strconv.FormatUint(uint64(resource.ProjectID), 10), nil
		}
		if resource.Type == "" || resource.ID == "" {
			return false, nil
		}
		projectID, err := strconv.ParseUint(binding.ScopeID, 10, 64)
		if err != nil {
			return false, nil
		}
		var count int64
		query := e.db.Model(&model.AccessProjectResource{}).
			Where("project_id = ? AND resource_type = ? AND resource_id = ?", uint(projectID), resource.Type, resource.ID)
		if resource.NodeID != 0 {
			query = query.Where("node_id = ?", resource.NodeID)
		}
		if err := query.Count(&count).Error; err != nil {
			return false, fmt.Errorf("check project resource membership: %w", err)
		}
		return count > 0, nil
	default:
		return false, nil
	}
}

func (e *Evaluator) isActiveUser(userID uint) (bool, error) {
	if userID == 0 {
		return false, nil
	}
	var user model.AccessUser
	if err := e.db.Select("id", "status").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("load access user: %w", err)
	}
	return user.Status == model.AccessUserStatusActive, nil
}

func (e *Evaluator) isGlobalAdministrator(userID uint) (bool, error) {
	var count int64
	err := e.db.Table("rbac_role_bindings AS rb").
		Joins("JOIN rbac_roles r ON r.id = rb.role_id").
		Where("rb.user_id = ? AND r.key = ? AND rb.scope_type = ? AND rb.scope_id = ?", userID, RoleAdministrator, model.AccessScopeGlobal, "*").
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("check global administrator binding: %w", err)
	}
	return count > 0, nil
}

package rbac

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
)

// AccessibleProjectRoots returns administrator-defined project roots covered by
// a permission. Resource-scoped website bindings inherit the root of projects
// containing that website, but never invent a root from browser input.
func (e *Evaluator) AccessibleProjectRoots(userID uint, permissionCode string, nodeID uint) ([]string, error) {
	active, err := e.isActiveUser(userID)
	if err != nil || !active {
		return nil, err
	}
	admin, err := e.isGlobalAdministrator(userID)
	if err != nil {
		return nil, err
	}
	if admin {
		return []string{string(filepath.Separator)}, nil
	}
	bindings, err := e.bindingsForPermission(userID, permissionCode)
	if err != nil {
		return nil, err
	}
	projectIDs := map[uint]struct{}{}
	for _, binding := range bindings {
		switch binding.ScopeType {
		case model.AccessScopeProject:
			id, err := strconv.ParseUint(binding.ScopeID, 10, 64)
			if err == nil && id > 0 {
				projectIDs[uint(id)] = struct{}{}
			}
		case model.AccessScopeResource:
			if binding.ResourceType != "website" && binding.ResourceType != "runtime" && binding.ResourceType != "database" && binding.ResourceType != "container" && binding.ResourceType != "compose" {
				continue
			}
			query := e.db.Model(&model.AccessProjectResource{}).
				Where("resource_type = ? AND resource_id = ?", binding.ResourceType, binding.ScopeID)
			if nodeID != 0 {
				query = query.Where("node_id = ?", nodeID)
			}
			var ids []uint
			if err := query.Pluck("project_id", &ids).Error; err != nil {
				return nil, fmt.Errorf("resolve resource project roots: %w", err)
			}
			for _, id := range ids {
				projectIDs[id] = struct{}{}
			}
		case model.AccessScopeNode:
			if nodeID != 0 && binding.ScopeID == strconv.FormatUint(uint64(nodeID), 10) {
				var ids []uint
				if err := e.db.Model(&model.AccessProjectResource{}).Where("node_id = ?", nodeID).Distinct("project_id").Pluck("project_id", &ids).Error; err != nil {
					return nil, fmt.Errorf("resolve node project roots: %w", err)
				}
				for _, id := range ids {
					projectIDs[id] = struct{}{}
				}
			}
		case model.AccessScopeGlobal:
			var ids []uint
			if err := e.db.Model(&model.AccessProject{}).Where("status = ?", "active").Pluck("id", &ids).Error; err != nil {
				return nil, fmt.Errorf("resolve global project roots: %w", err)
			}
			for _, id := range ids {
				projectIDs[id] = struct{}{}
			}
		}
	}
	if len(projectIDs) == 0 {
		return []string{}, nil
	}
	ids := make([]uint, 0, len(projectIDs))
	for id := range projectIDs {
		ids = append(ids, id)
	}
	var projects []model.AccessProject
	if err := e.db.Where("id IN (?) AND status = ?", ids, "active").Find(&projects).Error; err != nil {
		return nil, fmt.Errorf("load project roots: %w", err)
	}
	seen := map[string]struct{}{}
	roots := make([]string, 0, len(projects))
	for _, project := range projects {
		root := strings.TrimSpace(project.RootPath)
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(filepath.Clean(root))
		if err != nil || !filepath.IsAbs(abs) || abs == string(filepath.Separator) {
			continue
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		roots = append(roots, abs)
	}
	sort.Strings(roots)
	return roots, nil
}

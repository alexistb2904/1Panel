package rbac

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
)

// AccessibleProjectRoots returns administrator-defined roots for projects that
// are explicitly attached to the selected node. A project binding by itself is
// never a cross-node wildcard.
func (e *Evaluator) AccessibleProjectRoots(userID uint, permissionCode string, nodeID uint) ([]string, error) {
	active, err := e.isActiveUser(userID)
	if err != nil || !active { return nil, err }
	admin, err := e.isGlobalAdministrator(userID)
	if err != nil { return nil, err }
	if admin { return []string{string(filepath.Separator)}, nil }
	bindings, err := e.bindingsForPermission(userID, permissionCode)
	if err != nil { return nil, err }

	projectIDs := map[uint]struct{}{}
	addAttachedProject := func(projectID uint) error {
		attached, err := e.projectAttachedToNode(projectID, nodeID)
		if err != nil { return err }
		if attached { projectIDs[projectID] = struct{}{} }
		return nil
	}
	for _, binding := range bindings {
		switch binding.ScopeType {
		case model.AccessScopeProject:
			id, err := strconv.ParseUint(binding.ScopeID, 10, 64)
			if err == nil && id > 0 {
				if err := addAttachedProject(uint(id)); err != nil { return nil, err }
			}
		case model.AccessScopeResource:
			// Direct resource grants are disabled because stable resource names can
			// be deleted and recreated.
			continue
		case model.AccessScopeNode:
			if binding.ScopeID == strconv.FormatUint(uint64(nodeID), 10) {
				var ids []uint
				if err := e.db.Model(&model.AccessProjectNode{}).Where("node_id = ?", nodeID).Distinct("project_id").Pluck("project_id", &ids).Error; err != nil { return nil, err }
				for _, id := range ids { projectIDs[id] = struct{}{} }
			}
		case model.AccessScopeGlobal:
			var ids []uint
			if err := e.db.Table("rbac_project_nodes AS pn").
				Joins("JOIN rbac_projects p ON p.id = pn.project_id").
				Where("pn.node_id = ? AND p.status = ?", nodeID, "active").
				Distinct("pn.project_id").Pluck("pn.project_id", &ids).Error; err != nil { return nil, err }
			for _, id := range ids { projectIDs[id] = struct{}{} }
		}
	}
	if len(projectIDs) == 0 { return []string{}, nil }

	ids := make([]uint, 0, len(projectIDs))
	for id := range projectIDs { ids = append(ids, id) }
	type row struct { ProjectID uint; RootPath string }
	var rows []row
	if err := e.db.Table("rbac_project_nodes AS pn").
		Select("pn.project_id, pn.root_path").
		Joins("JOIN rbac_projects p ON p.id = pn.project_id").
		Where("pn.project_id IN (?) AND pn.node_id = ? AND p.status = ?", ids, nodeID, "active").
		Scan(&rows).Error; err != nil { return nil, err }

	seen := map[string]struct{}{}
	roots := make([]string, 0, len(rows))
	for _, item := range rows {
		root := strings.TrimSpace(item.RootPath)
		if root == "" { continue }
		abs, err := filepath.Abs(filepath.Clean(root))
		if err != nil || !filepath.IsAbs(abs) || abs == string(filepath.Separator) { continue }
		if _, ok := seen[abs]; ok { continue }
		seen[abs] = struct{}{}
		roots = append(roots, abs)
	}
	sort.Strings(roots)
	return roots, nil
}

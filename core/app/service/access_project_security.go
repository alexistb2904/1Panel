package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var forbiddenProjectRoots = map[string]struct{}{
	"/":     {},
	"/boot": {},
	"/dev":  {},
	"/etc":  {},
	"/proc": {},
	"/root": {},
	"/run":  {},
	"/sys":  {},
	"/usr":  {},
	"/var":  {},
}

func loadAccessProjectNodeInfos(db *gorm.DB, projectID uint, discloseRoots bool) ([]dto.AccessProjectNodeInfo, error) {
	var boundaries []model.AccessProjectNode
	if err := db.Where("project_id = ?", projectID).Order("node_id ASC").Find(&boundaries).Error; err != nil {
		return nil, err
	}
	items := make([]dto.AccessProjectNodeInfo, 0, len(boundaries))
	for _, boundary := range boundaries {
		item := dto.AccessProjectNodeInfo{NodeID: boundary.NodeID}
		if boundary.NodeID == 0 {
			item.Name = "Local / master"
			item.ExternalKey = "local"
		} else {
			var node model.AccessNodeScope
			if err := db.Select("id", "name", "external_key").First(&node, boundary.NodeID).Error; err == nil {
				item.Name = node.Name
				item.ExternalKey = node.ExternalKey
			}
		}
		if discloseRoots {
			item.RootPath = boundary.RootPath
		}
		items = append(items, item)
	}
	return items, nil
}

func ListAccessProjectSecurity() ([]dto.AccessProjectSecurityInfo, error) {
	var projects []model.AccessProject
	if err := global.DB.Order("name ASC").Find(&projects).Error; err != nil {
		return nil, err
	}
	result := make([]dto.AccessProjectSecurityInfo, 0, len(projects))
	for _, project := range projects {
		item := dto.AccessProjectSecurityInfo{ID: project.ID, Name: project.Name, Slug: project.Slug, Status: project.Status}
		nodes, err := loadAccessProjectNodeInfos(global.DB, project.ID, true)
		if err != nil { return nil, err }
		item.Nodes = nodes
		for _, node := range nodes {
			if node.NodeID == 0 { item.RootPath = node.RootPath; break }
		}
		result = append(result, item)
	}
	return result, nil
}

func UpdateAccessProjectRoot(req dto.AccessProjectRootUpdate) error {
	return global.DB.Transaction(func(tx *gorm.DB) error {
		var project model.AccessProject
		if err := tx.First(&project, req.ID).Error; err != nil {
			return err
		}
		if req.NodeID > 0 {
			var count int64
			if err := tx.Model(&model.AccessNodeScope{}).Where("id = ? AND status = ?", req.NodeID, model.AccessUserStatusActive).Count(&count).Error; err != nil {
				return err
			}
			if count == 0 {
				return errors.New("project node is unknown or disabled")
			}
		}

		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if !enabled {
			var resources int64
			if err := tx.Model(&model.AccessProjectResource{}).Where("project_id = ? AND node_id = ?", project.ID, req.NodeID).Count(&resources).Error; err != nil {
				return err
			}
			if resources != 0 {
				return errors.New("project node cannot be detached while project resources still exist on it")
			}
			if err := tx.Where("project_id = ? AND node_id = ?", project.ID, req.NodeID).Delete(&model.AccessProjectNode{}).Error; err != nil {
				return err
			}
			if req.NodeID == 0 {
				return tx.Model(&project).Update("root_path", "").Error
			}
			return nil
		}

		root, err := normalizeProjectRootPathForNode(req.NodeID, req.RootPath)
		if err != nil {
			return err
		}
		item := model.AccessProjectNode{ProjectID: project.ID, NodeID: req.NodeID, RootPath: root}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "project_id"}, {Name: "node_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"root_path", "updated_at"}),
		}).Create(&item).Error; err != nil {
			return err
		}
		if req.NodeID == 0 {
			return tx.Model(&project).Update("root_path", root).Error
		}
		return nil
	})
}

func normalizeProjectRootPathForNode(nodeID uint, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("project rootPath must be absolute")
	}
	clean := filepath.Clean(raw)
	if _, blocked := forbiddenProjectRoots[clean]; blocked {
		return "", errors.New("project rootPath is too broad or points to a protected system directory")
	}
	for _, sensitive := range []string{"/etc", "/proc", "/sys", "/dev", "/run", "/var/run/docker.sock"} {
		if pathContains(clean, sensitive) {
			return "", errors.New("project rootPath would include protected host resources")
		}
	}

	// Core can resolve and verify the local filesystem. Remote roots are stored
	// as normalized absolute paths and are revalidated by the Agent on the
	// selected node immediately before every scoped filesystem/container use.
	if nodeID != 0 {
		return clean, nil
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", errors.New("local project rootPath must already exist and be resolvable")
	}
	resolved = filepath.Clean(resolved)
	if _, blocked := forbiddenProjectRoots[resolved]; blocked {
		return "", errors.New("project rootPath resolves to a protected system directory")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("local project rootPath must be an existing directory")
	}
	for _, sensitive := range []string{"/etc", "/proc", "/sys", "/dev", "/run", "/var/run/docker.sock"} {
		if pathContains(resolved, sensitive) {
			return "", errors.New("project rootPath would include protected host resources")
		}
	}
	return resolved, nil
}

func normalizeProjectRootPath(raw string) (string, error) {
	return normalizeProjectRootPathForNode(0, raw)
}

func pathContains(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

func EnsureAccessProjectRootColumn(tx *gorm.DB) error {
	return tx.AutoMigrate(&model.AccessProject{}, &model.AccessProjectNode{})
}

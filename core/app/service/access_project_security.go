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

func ListAccessProjectSecurity() ([]dto.AccessProjectSecurityInfo, error) {
	var projects []model.AccessProject
	if err := global.DB.Order("name ASC").Find(&projects).Error; err != nil {
		return nil, err
	}
	result := make([]dto.AccessProjectSecurityInfo, 0, len(projects))
	for _, project := range projects {
		result = append(result, dto.AccessProjectSecurityInfo{
			ID: project.ID, Name: project.Name, Slug: project.Slug,
			RootPath: project.RootPath, Status: project.Status,
		})
	}
	return result, nil
}

func UpdateAccessProjectRoot(req dto.AccessProjectRootUpdate) error {
	var project model.AccessProject
	if err := global.DB.First(&project, req.ID).Error; err != nil {
		return err
	}
	root, err := normalizeProjectRootPath(req.RootPath)
	if err != nil {
		return err
	}
	return global.DB.Model(&project).Update("root_path", root).Error
}

func normalizeProjectRootPath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("project rootPath must be absolute")
	}
	clean := filepath.Clean(raw)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", errors.New("project rootPath must already exist and be resolvable")
	}
	resolved = filepath.Clean(resolved)
	if _, blocked := forbiddenProjectRoots[resolved]; blocked {
		return "", errors.New("project rootPath is too broad or points to a protected system directory")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("project rootPath must be an existing directory")
	}

	// A project boundary must never be able to encompass Linux pseudo-filesystems
	// or the Docker daemon socket through a broad ancestor such as /var or /run.
	for _, sensitive := range []string{"/etc", "/proc", "/sys", "/dev", "/run", "/var/run/docker.sock"} {
		if pathContains(resolved, sensitive) {
			return "", errors.New("project rootPath would include protected host resources")
		}
	}
	return resolved, nil
}

func pathContains(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

func EnsureAccessProjectRootColumn(tx *gorm.DB) error {
	return tx.AutoMigrate(&model.AccessProject{})
}

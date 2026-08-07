package service

import (
	"context"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/utils/docker"
	"github.com/docker/docker/api/types/container"
)

const rbacCollectionPageSize = 1000000

func PageContainersForRBAC(req dto.PageContainer, allowed []string) (int64, []dto.ContainerInfo, error) {
	allowedSet, err := resolveAllowedContainerIdentifiers(allowed)
	if err != nil {
		return 0, nil, err
	}
	allReq := req
	allReq.Page = 1
	allReq.PageSize = rbacCollectionPageSize
	_, raw, err := NewIContainerService().Page(allReq)
	if err != nil {
		return 0, nil, err
	}
	items, _ := raw.([]dto.ContainerInfo)
	filtered := make([]dto.ContainerInfo, 0, len(items))
	for _, item := range items {
		if containerAllowed(allowedSet, item.ContainerID, item.Name) {
			filtered = append(filtered, item)
		}
	}
	return paginateContainerInfo(filtered, req.Page, req.PageSize)
}

func ListContainersForRBAC(allowed []string) ([]dto.ContainerOptions, error) {
	allowedSet, err := resolveAllowedContainerIdentifiers(allowed)
	if err != nil {
		return nil, err
	}
	items := NewIContainerService().List()
	filtered := make([]dto.ContainerOptions, 0, len(items))
	for _, item := range items {
		if containerAllowed(allowedSet, "", item.Name) {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func ContainerStatsForRBAC(allowed []string) ([]dto.ContainerListStats, error) {
	allowedSet, err := resolveAllowedContainerIdentifiers(allowed)
	if err != nil {
		return nil, err
	}
	items, err := NewIContainerService().ContainerListStats()
	if err != nil {
		return nil, err
	}
	filtered := make([]dto.ContainerListStats, 0, len(items))
	for _, item := range items {
		if containerAllowed(allowedSet, item.ContainerID, "") {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func PageComposeForRBAC(req dto.SearchWithPage, allowed []string) (int64, []dto.ComposeInfo, error) {
	allowedSet := simpleAllowedSet(allowed)
	allReq := req
	allReq.Page = 1
	allReq.PageSize = rbacCollectionPageSize
	_, raw, err := NewIContainerService().PageCompose(allReq)
	if err != nil {
		return 0, nil, err
	}
	items, _ := raw.([]dto.ComposeInfo)
	filtered := make([]dto.ComposeInfo, 0, len(items))
	for _, item := range items {
		if _, ok := allowedSet[item.Name]; ok {
			filtered = append(filtered, item)
		}
	}
	return paginateComposeInfo(filtered, req.Page, req.PageSize)
}

// ResolveContainerTarget verifies that a request identifier (name, full ID or
// unique ID prefix accepted by Docker) resolves to one of the project-owned
// identifiers delivered by Core.
func ResolveContainerTarget(target string, allowed []string) (bool, error) {
	allowedSet, err := resolveAllowedContainerIdentifiers(allowed)
	if err != nil {
		return false, err
	}
	client, err := docker.NewDockerClient()
	if err != nil {
		return false, err
	}
	defer client.Close()
	inspected, err := client.ContainerInspect(context.Background(), target)
	if err != nil {
		return false, err
	}
	name := strings.TrimPrefix(inspected.Name, "/")
	return containerAllowed(allowedSet, inspected.ID, name), nil
}

func resolveAllowedContainerIdentifiers(allowed []string) (map[string]struct{}, error) {
	set := simpleAllowedSet(allowed)
	if len(set) == 0 {
		return set, nil
	}
	client, err := docker.NewDockerClient()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	items, err := client.ContainerList(context.Background(), container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		name := ""
		if len(item.Names) > 0 {
			name = strings.TrimPrefix(item.Names[0], "/")
		}
		if _, byName := set[name]; byName {
			set[item.ID] = struct{}{}
		}
		if _, byID := set[item.ID]; byID {
			if name != "" {
				set[name] = struct{}{}
			}
		}
		for registered := range set {
			if len(registered) >= 12 && strings.HasPrefix(item.ID, registered) {
				set[item.ID] = struct{}{}
				if name != "" {
					set[name] = struct{}{}
				}
			}
		}
	}
	return set, nil
}

func simpleAllowedSet(allowed []string) map[string]struct{} {
	set := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		if value := strings.TrimSpace(item); value != "" {
			set[value] = struct{}{}
		}
	}
	return set
}

func containerAllowed(set map[string]struct{}, id, name string) bool {
	if _, ok := set[id]; ok && id != "" {
		return true
	}
	if _, ok := set[name]; ok && name != "" {
		return true
	}
	for registered := range set {
		if id != "" && len(registered) >= 12 && strings.HasPrefix(id, registered) {
			return true
		}
	}
	return false
}

func paginateContainerInfo(items []dto.ContainerInfo, page, pageSize int) (int64, []dto.ContainerInfo, error) {
	total := len(items)
	start, end := pageBounds(total, page, pageSize)
	return int64(total), items[start:end], nil
}

func paginateComposeInfo(items []dto.ComposeInfo, page, pageSize int) (int64, []dto.ComposeInfo, error) {
	total := len(items)
	start, end := pageBounds(total, page, pageSize)
	return int64(total), items[start:end], nil
}

func pageBounds(total, page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return start, end
}

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
	if err != nil { return 0, nil, err }
	allReq := req
	allReq.Page = 1
	allReq.PageSize = rbacCollectionPageSize
	_, raw, err := NewIContainerService().Page(allReq)
	if err != nil { return 0, nil, err }
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
	if err != nil { return nil, err }
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
	if err != nil { return nil, err }
	items, err := NewIContainerService().ContainerListStats()
	if err != nil { return nil, err }
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
	if err != nil { return 0, nil, err }
	items, _ := raw.([]dto.ComposeInfo)
	filtered := make([]dto.ComposeInfo, 0, len(items))
	for _, item := range items {
		if _, ok := allowedSet[item.Name]; ok {
			// docker.compose.view must not disclose environment values or the
			// host filesystem layout. Those details are either secret-bearing or
			// infrastructure metadata and require a dedicated capability.
			item.Env = ""
			item.ConfigFile = ""
			item.Workdir = ""
			item.Path = ""
			filtered = append(filtered, item)
		}
	}
	return paginateComposeInfo(filtered, req.Page, req.PageSize)
}

// ResolveContainerTarget verifies any Docker-accepted request target (exact
// name, full ID or unique ID prefix) by first asking Docker for the canonical
// object and then comparing that canonical object with containers resolved from
// exact project-owned names. A project-owned name is never interpreted as an
// ID prefix, even when the name happens to be 12+ hexadecimal characters.
func ResolveContainerTarget(target string, allowed []string) (bool, error) {
	allowedSet, err := resolveAllowedContainerIdentifiers(allowed)
	if err != nil { return false, err }
	client, err := docker.NewDockerClient()
	if err != nil { return false, err }
	defer client.Close()
	inspected, err := client.ContainerInspect(context.Background(), target)
	if err != nil { return false, err }
	name := strings.TrimPrefix(inspected.Name, "/")
	return containerAllowed(allowedSet, inspected.ID, name), nil
}

// RemoveContainersForRBAC executes scoped deletion synchronously. The legacy
// ContainerOperation path schedules remove work in a background task and returns
// success before Docker has actually removed anything; Core therefore cannot
// safely clean ownership from that acknowledgement. The scoped path uses the
// same per-container operation lock but waits for Docker to confirm removal
// before returning success, so the Core ownership cleanup becomes transactional
// with the externally observable lifecycle.
func RemoveContainersForRBAC(names []string) error {
	client, err := docker.NewDockerClient()
	if err != nil { return err }
	defer client.Close()
	ctx := context.Background()
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" { continue }
		unlock := containerOperationLock.lock(name)
		err := client.ContainerRemove(ctx, name, container.RemoveOptions{RemoveVolumes: true, Force: true})
		unlock()
		if err != nil { return err }
	}
	return nil
}

// resolveAllowedContainerIdentifiers treats every Core ownership identifier as
// a container NAME. Full IDs are added only after Docker itself confirms that
// an exact container name is owned. This intentionally removes the ambiguous
// name/ID-prefix namespace that allowed a crafted name to authorize another
// project's container.
func resolveAllowedContainerIdentifiers(allowed []string) (map[string]struct{}, error) {
	ownedNames := simpleAllowedSet(allowed)
	resolved := make(map[string]struct{}, len(ownedNames)*2)
	if len(ownedNames) == 0 { return resolved, nil }

	client, err := docker.NewDockerClient()
	if err != nil { return nil, err }
	defer client.Close()
	items, err := client.ContainerList(context.Background(), container.ListOptions{All: true})
	if err != nil { return nil, err }
	for _, item := range items {
		for _, rawName := range item.Names {
			name := strings.TrimPrefix(rawName, "/")
			if _, ok := ownedNames[name]; !ok { continue }
			resolved[name] = struct{}{}
			if item.ID != "" { resolved[item.ID] = struct{}{} }
			break
		}
	}
	return resolved, nil
}

func simpleAllowedSet(allowed []string) map[string]struct{} {
	set := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		if value := strings.TrimSpace(item); value != "" { set[value] = struct{}{} }
	}
	return set
}

func containerAllowed(set map[string]struct{}, id, name string) bool {
	if id != "" {
		if _, ok := set[id]; ok { return true }
	}
	if name != "" {
		if _, ok := set[name]; ok { return true }
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
	if page < 1 { page = 1 }
	if pageSize < 1 { pageSize = 10 }
	start := (page - 1) * pageSize
	if start > total { start = total }
	end := start + pageSize
	if end > total { end = total }
	return start, end
}

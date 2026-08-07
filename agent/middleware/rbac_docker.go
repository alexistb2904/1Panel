package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const (
	headerDockerRBACMode        = "X-Panel-RBAC-Mode"
	headerDockerRBACResourceIDs = "X-Panel-RBAC-Resource-IDs"
	headerDockerRBACRestricted  = "X-Panel-RBAC-Restricted"
	headerDockerProjectRoot     = "X-Panel-RBAC-Project-Root"
	headerDockerInternalRequest = "X-Panel-Internal-Request"

	dockerRBACModeAll = "all"
	dockerRBACModeIDs = "ids"
)

// DockerRBAC is the Agent-side enforcement boundary. Core decides permissions
// and project scope; Agent verifies concrete Docker targets and rejects runtime
// definitions that could turn project access into host-root access.
func DockerRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerDockerInternalRequest) == "1" {
			c.Next()
			return
		}
		mode := c.GetHeader(headerDockerRBACMode)
		if mode == "" {
			denyDocker(c, "Missing RBAC context")
			return
		}
		if mode == dockerRBACModeAll {
			c.Next()
			return
		}
		if mode != dockerRBACModeIDs || c.GetHeader(headerDockerRBACRestricted) != "1" {
			denyDocker(c, "Invalid restricted Docker context")
			return
		}
		allowed := splitDockerIDs(c.GetHeader(headerDockerRBACResourceIDs))
		if handleRestrictedDockerCollection(c, allowed) {
			return
		}

		path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/containers")
		if path == "" && c.Request.Method == http.MethodPost {
			var req dto.ContainerOperate
			if !bindReusableJSON(c, &req) {
				return
			}
			if !containsString(allowed, req.Name) {
				denyDocker(c, "Container was not reserved for this project")
				return
			}
			if err := validateRestrictedContainer(req, c.GetHeader(headerDockerProjectRoot)); err != nil {
				denyDocker(c, err.Error())
				return
			}
			c.Next()
			return
		}
		if path == "/update" {
			var req dto.ContainerOperate
			if !bindReusableJSON(c, &req) {
				return
			}
			if !authorizedContainerTarget(req.Name, allowed) {
				denyDocker(c, "Container access denied")
				return
			}
			if err := validateRestrictedContainer(req, c.GetHeader(headerDockerProjectRoot)); err != nil {
				denyDocker(c, err.Error())
				return
			}
			c.Next()
			return
		}
		if path == "/compose" && c.Request.Method == http.MethodPost {
			var req dto.ComposeCreate
			if !bindReusableJSON(c, &req) {
				return
			}
			if !containsString(allowed, req.Name) {
				denyDocker(c, "Compose project was not reserved for this project")
				return
			}
			if req.From != "edit" {
				denyDocker(c, "Restricted Compose creation only accepts inline reviewed content")
				return
			}
			if err := validateRestrictedCompose(req.File, c.GetHeader(headerDockerProjectRoot)); err != nil {
				denyDocker(c, err.Error())
				return
			}
			c.Next()
			return
		}
		if path == "/compose/test" {
			var req dto.ComposeCreate
			if !bindReusableJSON(c, &req) {
				return
			}
			if req.From != "edit" {
				denyDocker(c, "Restricted Compose validation only accepts inline content")
				return
			}
			if err := validateRestrictedCompose(req.File, c.GetHeader(headerDockerProjectRoot)); err != nil {
				denyDocker(c, err.Error())
				return
			}
			c.Next()
			return
		}
		if path == "/compose/update" {
			var req dto.ComposeUpdate
			if !bindReusableJSON(c, &req) {
				return
			}
			if !containsString(allowed, req.Name) {
				denyDocker(c, "Compose access denied")
				return
			}
			if err := validateRestrictedCompose(req.Content, c.GetHeader(headerDockerProjectRoot)); err != nil {
				denyDocker(c, err.Error())
				return
			}
			c.Next()
			return
		}

		resourceType, targets, ok := resolveRestrictedDockerTargets(c)
		if !ok || len(targets) == 0 {
			denyDocker(c, "Unable to resolve Docker authorization target")
			return
		}
		for _, target := range targets {
			if resourceType == "container" {
				if !authorizedContainerTarget(target, allowed) {
					denyDocker(c, "Container access denied")
					return
				}
			} else if !containsString(allowed, target) {
				denyDocker(c, "Compose access denied")
				return
			}
		}
		c.Next()
	}
}

func handleRestrictedDockerCollection(c *gin.Context, allowed []string) bool {
	path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/containers")
	switch path {
	case "/search":
		var req dto.PageContainer
		if err := helper.CheckBindAndValidate(&req, c); err != nil {
			return true
		}
		total, items, err := service.PageContainersForRBAC(req, allowed)
		if err != nil {
			helper.InternalServer(c, err)
			return true
		}
		helper.SuccessWithData(c, dto.PageResult{Items: items, Total: total})
		return true
	case "/list":
		items, err := service.ListContainersForRBAC(allowed)
		if err != nil {
			helper.InternalServer(c, err)
			return true
		}
		helper.SuccessWithData(c, items)
		return true
	case "/stats":
		items, err := service.ContainerStatsForRBAC(allowed)
		if err != nil {
			helper.InternalServer(c, err)
			return true
		}
		helper.SuccessWithData(c, items)
		return true
	case "/compose/search":
		var req dto.SearchWithPage
		if err := helper.CheckBindAndValidate(&req, c); err != nil {
			return true
		}
		total, items, err := service.PageComposeForRBAC(req, allowed)
		if err != nil {
			helper.InternalServer(c, err)
			return true
		}
		helper.SuccessWithData(c, dto.PageResult{Items: items, Total: total})
		return true
	default:
		return false
	}
}

func resolveRestrictedDockerTargets(c *gin.Context) (string, []string, bool) {
	path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/containers")
	body, payload, err := readDockerJSON(c)
	if err != nil {
		return "", nil, false
	}
	if body != nil {
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
	}
	value := func(key string) string { valueString(payload[key]) }
	values := func(key string) []string { valueStrings(payload[key]) }
	switch path {
	case "/info", "/users":
		return "container", []string{value("name")}, true
	case "/operate":
		return "container", values("names"), true
	case "/upgrade":
		return "container", values("names"), true
	case "/rename":
		return "container", []string{value("name")}, true
	case "/commit":
		return "container", []string{value("containerID")}, true
	case "/files/search", "/files/content", "/files/size", "/files/del", "/files/download":
		return "container", []string{value("containerID")}, true
	case "/inspect":
		typeName := value("type")
		if typeName == "container" || typeName == "compose" {
			return typeName, []string{value("id")}, true
		}
	case "/compose/env", "/compose/logs", "/compose/operate", "/compose/pin":
		return "compose", []string{value("name")}, true
	}
	return "", nil, false
}

func validateRestrictedContainer(req dto.ContainerOperate, root string) error {
	if req.Privileged {
		return errors.New("privileged containers are administrator-only")
	}
	for _, network := range req.Networks {
		name := strings.ToLower(strings.TrimSpace(network.Network))
		if name != "" && name != "bridge" && name != "none" {
			return fmt.Errorf("custom Docker network %q requires administrator approval", network.Network)
		}
	}
	for _, port := range req.ExposedPorts {
		if port.HostPort == "" {
			continue
		}
		hostPort, err := strconv.Atoi(port.HostPort)
		if err == nil && hostPort > 0 && hostPort < 1024 {
			return fmt.Errorf("binding privileged host port %d is administrator-only", hostPort)
		}
		if port.HostIP != "" && net.ParseIP(port.HostIP) == nil {
			return fmt.Errorf("invalid host IP %q", port.HostIP)
		}
	}
	for _, host := range req.ExtraHosts {
		if strings.EqualFold(strings.TrimSpace(host.IP), "host-gateway") {
			return errors.New("host-gateway mappings are administrator-only")
		}
	}
	for _, volume := range req.Volumes {
		typeName := strings.ToLower(strings.TrimSpace(volume.Type))
		switch typeName {
		case "bind":
			if err := validateProjectHostPath(root, volume.SourceDir); err != nil {
				return fmt.Errorf("unsafe bind mount %q: %w", volume.SourceDir, err)
			}
		case "volume":
			if strings.TrimSpace(volume.SourceDir) != "" {
				return errors.New("mounting existing named Docker volumes is administrator-only; use project Compose volumes")
			}
		case "tmpfs":
			// tmpfs has no host source and stays inside the container boundary.
		default:
			return fmt.Errorf("volume type %q is not allowed for restricted containers", volume.Type)
		}
	}
	return nil
}

func validateProjectHostPath(root, source string) error {
	root = strings.TrimSpace(root)
	source = strings.TrimSpace(source)
	if root == "" {
		return errors.New("project rootPath is required for host bind mounts")
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(source) {
		return errors.New("project and bind paths must be absolute")
	}
	rootInfo, err := os.Stat(root)
	if err != nil || !rootInfo.IsDir() {
		return errors.New("project rootPath must exist and be a directory")
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return errors.New("bind source must already exist")
	}
	_ = sourceInfo
	resolvedRoot, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return errors.New("cannot resolve project rootPath")
	}
	resolvedSource, err := filepath.EvalSymlinks(filepath.Clean(source))
	if err != nil {
		return errors.New("cannot resolve bind source")
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedSource)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return errors.New("bind source escapes the project rootPath")
	}
	return nil
}

func validateRestrictedCompose(content, root string) error {
	if strings.TrimSpace(content) == "" {
		return errors.New("Compose content is required")
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		return fmt.Errorf("invalid Compose YAML: %w", err)
	}
	servicesNode, ok := document["services"].(map[string]any)
	if !ok || len(servicesNode) == 0 {
		return errors.New("Compose services are required")
	}
	declaredVolumes, err := validateComposeTopLevelResources(document, "volumes")
	if err != nil {
		return err
	}
	declaredNetworks, err := validateComposeTopLevelResources(document, "networks")
	if err != nil {
		return err
	}
	if nonEmpty(document["secrets"]) || nonEmpty(document["configs"]) {
		return errors.New("Compose secrets/configs are administrator-only until scoped secret storage is implemented")
	}

	for name, rawService := range servicesNode {
		serviceDef, ok := rawService.(map[string]any)
		if !ok {
			return fmt.Errorf("service %s has an invalid definition", name)
		}
		if boolValue(serviceDef["privileged"]) {
			return fmt.Errorf("service %s: privileged mode is administrator-only", name)
		}
		if nonEmpty(serviceDef["cap_add"]) || nonEmpty(serviceDef["devices"]) || nonEmpty(serviceDef["device_cgroup_rules"]) {
			return fmt.Errorf("service %s: Linux capabilities/devices are administrator-only", name)
		}
		for _, key := range []string{"pid", "ipc", "uts", "cgroup", "userns_mode"} {
			if valueString(serviceDef[key]) != "" && valueString(serviceDef[key]) != "private" {
				return fmt.Errorf("service %s: %s namespace sharing is administrator-only", name, key)
			}
		}
		networkMode := strings.ToLower(valueString(serviceDef["network_mode"]))
		if networkMode != "" && networkMode != "bridge" && networkMode != "none" {
			return fmt.Errorf("service %s: network_mode %q is not allowed", name, networkMode)
		}
		if nonEmpty(serviceDef["volumes_from"]) || nonEmpty(serviceDef["extends"]) {
			return fmt.Errorf("service %s: cross-container/compose inheritance is administrator-only", name)
		}
		if nonEmpty(serviceDef["build"]) {
			return fmt.Errorf("service %s: Compose build contexts are disabled for restricted projects; use an image", name)
		}
		if nonEmpty(serviceDef["env_file"]) {
			return fmt.Errorf("service %s: env_file host reads are disabled; use project environment values", name)
		}
		if nonEmpty(serviceDef["secrets"]) || nonEmpty(serviceDef["configs"]) {
			return fmt.Errorf("service %s: secrets/configs are administrator-only", name)
		}
		if opts, ok := serviceDef["security_opt"].([]any); ok {
			for _, opt := range opts {
				if strings.Contains(strings.ToLower(fmt.Sprint(opt)), "unconfined") {
					return fmt.Errorf("service %s: unconfined security options are administrator-only", name)
				}
			}
		}
		if err := validateComposeServiceVolumes(name, serviceDef["volumes"], root, declaredVolumes); err != nil {
			return err
		}
		if err := validateComposeServiceNetworks(name, serviceDef["networks"], declaredNetworks); err != nil {
			return err
		}
	}
	return nil
}

func validateComposeTopLevelResources(document map[string]any, key string) (map[string]struct{}, error) {
	result := map[string]struct{}{}
	raw := document[key]
	if raw == nil {
		return result, nil
	}
	items, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Compose %s must be a mapping", key)
	}
	for name, rawDefinition := range items {
		result[name] = struct{}{}
		definition, _ := rawDefinition.(map[string]any)
		if len(definition) == 0 {
			continue
		}
		if boolValue(definition["external"]) || valueString(definition["name"]) != "" {
			return nil, fmt.Errorf("Compose %s %s cannot reference or rename an external resource", key, name)
		}
		if nonEmpty(definition["driver_opts"]) {
			return nil, fmt.Errorf("Compose %s %s driver_opts are administrator-only", key, name)
		}
		if driver := strings.ToLower(valueString(definition["driver"])); driver != "" && driver != "local" && driver != "bridge" {
			return nil, fmt.Errorf("Compose %s %s driver %q is not allowed", key, name, driver)
		}
	}
	return result, nil
}

func validateComposeServiceVolumes(serviceName string, raw any, root string, declared map[string]struct{}) error {
	items, ok := raw.([]any)
	if !ok && raw != nil {
		return fmt.Errorf("service %s: volumes must be a list", serviceName)
	}
	for _, item := range items {
		switch value := item.(type) {
		case string:
			source := composeShortVolumeSource(value)
			if source == "" {
				continue
			}
			if filepath.IsAbs(source) {
				if err := validateProjectHostPath(root, source); err != nil {
					return fmt.Errorf("service %s: unsafe bind %q: %w", serviceName, source, err)
				}
				continue
			}
			if _, ok := declared[source]; !ok {
				return fmt.Errorf("service %s: named volume %s must be declared inside this project Compose", serviceName, source)
			}
		case map[string]any:
			typeName := strings.ToLower(valueString(value["type"]))
			source := valueString(value["source"])
			switch typeName {
			case "bind":
				if err := validateProjectHostPath(root, source); err != nil {
					return fmt.Errorf("service %s: unsafe bind %q: %w", serviceName, source, err)
				}
			case "volume", "":
				if source != "" {
					if _, ok := declared[source]; !ok {
						return fmt.Errorf("service %s: named volume %s is not project-owned", serviceName, source)
					}
				}
			case "tmpfs":
			default:
				return fmt.Errorf("service %s: volume type %q is not allowed", serviceName, typeName)
			}
		default:
			return fmt.Errorf("service %s: invalid volume definition", serviceName)
		}
	}
	return nil
}

func validateComposeServiceNetworks(serviceName string, raw any, declared map[string]struct{}) error {
	if raw == nil {
		return nil
	}
	var names []string
	switch value := raw.(type) {
	case []any:
		for _, item := range value {
			names = append(names, valueString(item))
		}
	case map[string]any:
		for name := range value {
			names = append(names, name)
		}
	default:
		return fmt.Errorf("service %s: invalid networks definition", serviceName)
	}
	for _, name := range names {
		if name == "default" || name == "" {
			continue
		}
		if _, ok := declared[name]; !ok {
			return fmt.Errorf("service %s: network %s must be declared in the same Compose project", serviceName, name)
		}
	}
	return nil
}

func composeShortVolumeSource(value string) string {
	parts := strings.Split(value, ":")
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func authorizedContainerTarget(target string, allowed []string) bool {
	if strings.TrimSpace(target) == "" {
		return false
	}
	ok, err := service.ResolveContainerTarget(target, allowed)
	return err == nil && ok
}

func splitDockerIDs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func containsString(items []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, item := range items {
		if strings.TrimSpace(item) == target {
			return true
		}
	}
	return false
}

func bindReusableJSON(c *gin.Context, target any) bool {
	body, _, err := readDockerJSON(c)
	if err != nil {
		helper.BadRequest(c, err)
		return false
	}
	if err := json.Unmarshal(body, target); err != nil {
		helper.BadRequest(c, err)
		return false
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	return true
}

func readDockerJSON(c *gin.Context) ([]byte, map[string]any, error) {
	if c.Request.Body == nil {
		return nil, map[string]any{}, nil
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, nil, err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 {
		return body, map[string]any{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	payload := map[string]any{}
	if err := decoder.Decode(&payload); err != nil {
		return body, nil, err
	}
	return body, payload, nil
}

func valueString(raw any) string {
	if value, ok := raw.(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func valueStrings(raw any) []string {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if value := valueString(item); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func boolValue(raw any) bool {
	value, _ := raw.(bool)
	return value
}

func nonEmpty(raw any) bool {
	if raw == nil {
		return false
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value) != ""
	case []any:
		return len(value) > 0
	case map[string]any:
		return len(value) > 0
	case bool:
		return value
	default:
		return true
	}
}

func denyDocker(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"code": http.StatusForbidden, "message": message})
	c.Abort()
}

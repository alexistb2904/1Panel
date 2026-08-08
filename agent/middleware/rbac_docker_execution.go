package middleware

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// DockerRestrictedExecution runs after DockerRBAC has resolved and authorized
// the target. It closes execution-level gaps that cannot safely be represented
// as a simple resource-ID filter: asynchronous creation, secret-bearing raw
// inspect output and Compose features that can reach host/global resources.
func DockerRestrictedExecution() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerDockerInternalRequest) == "1" || c.GetHeader(headerDockerRBACMode) == dockerRBACModeAll {
			c.Next()
			return
		}
		if c.GetHeader(headerDockerRBACMode) != dockerRBACModeIDs || c.GetHeader(headerDockerRBACRestricted) != "1" {
			c.Next()
			return
		}

		path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/containers")
		switch {
		case path == "" && c.Request.Method == http.MethodPost:
			var req dto.ContainerOperate
			if !bindReusableJSON(c, &req) { return }
			if err := validateRestrictedContainerSecurityExtras(req); err != nil {
				denyDocker(c, err.Error())
				return
			}
			// Restricted creates must be synchronous. Core's two-phase ownership
			// may only activate after the container has actually been created and
			// started, never merely after a task has been queued.
			if err := service.NewIContainerService().ContainerCreate(req, false); err != nil {
				helper.InternalServer(c, err)
				c.Abort()
				return
			}
			helper.Success(c)
			c.Abort()
			return

		case path == "/info" && c.Request.Method == http.MethodPost:
			var req dto.OperationWithName
			if !bindReusableJSON(c, &req) { return }
			info, err := service.NewIContainerService().ContainerInfo(req)
			if err != nil {
				helper.InternalServer(c, err)
				c.Abort()
				return
			}
			redactContainerInfoForRBAC(info)
			helper.SuccessWithData(c, info)
			c.Abort()
			return

		case path == "/inspect":
			// Docker inspect includes environment variables, labels, mount source
			// paths and other secret-bearing implementation details. A future
			// scoped projection can expose selected fields, but raw inspect is not
			// a safe "view" primitive for a shared host.
			denyDocker(c, "Raw Docker inspect is administrator-only; use the redacted container info endpoint")
			return

		case path == "/compose", path == "/compose/test":
			var req dto.ComposeCreate
			if !bindReusableJSON(c, &req) { return }
			if err := validateRestrictedComposeExtraPolicy(req.File); err != nil {
				denyDocker(c, err.Error())
				return
			}
			c.Next()
			return

		case path == "/compose/update":
			var req dto.ComposeUpdate
			if !bindReusableJSON(c, &req) { return }
			if err := validateRestrictedComposeExtraPolicy(req.Content); err != nil {
				denyDocker(c, err.Error())
				return
			}
			c.Next()
			return
		}
		c.Next()
	}
}

func redactContainerInfoForRBAC(info *dto.ContainerOperate) {
	if info == nil { return }
	info.Env = nil
	info.Labels = nil
	info.DNS = nil
	info.ExtraHosts = nil
	for i := range info.Volumes {
		// The container destination is useful to understand the application;
		// host source paths are infrastructure metadata and may contain another
		// secret-bearing mount layout even when the target container is owned.
		info.Volumes[i].SourceDir = ""
	}
}

func validateRestrictedContainerSecurityExtras(req dto.ContainerOperate) error {
	for _, raw := range req.Labels {
		key := strings.TrimSpace(strings.SplitN(raw, "=", 2)[0])
		if isReservedDockerLabel(key) {
			return fmt.Errorf("Docker label %q is reserved for platform/Compose ownership", key)
		}
	}
	for _, port := range req.ExposedPorts {
		if host := net.ParseIP(strings.TrimSpace(port.HostIP)); host != nil && (host.IsUnspecified() || host.IsLoopback()) {
			// Explicit 0.0.0.0/:: is normal for a published application port and
			// loopback is less exposed, so both remain permitted. Parsing here is
			// intentionally retained to reject malformed values in the base policy.
			continue
		}
	}
	return nil
}

func validateRestrictedComposeExtraPolicy(content string) error {
	if strings.TrimSpace(content) == "" { return errors.New("Compose content is required") }
	var document map[string]any
	if err := yaml.Unmarshal([]byte(content), &document); err != nil { return fmt.Errorf("invalid Compose YAML: %w", err) }
	for _, key := range []string{"include"} {
		if nonEmpty(document[key]) {
			return fmt.Errorf("Compose %s is administrator-only because it can load host/external configuration", key)
		}
	}
	services, ok := document["services"].(map[string]any)
	if !ok { return errors.New("Compose services are required") }
	for serviceName, raw := range services {
		serviceDef, ok := raw.(map[string]any)
		if !ok { return fmt.Errorf("service %s has an invalid definition", serviceName) }
		for _, key := range []string{"cgroup_parent", "runtime", "isolation", "storage_opt", "develop"} {
			if nonEmpty(serviceDef[key]) {
				return fmt.Errorf("service %s: %s is administrator-only on shared hosts", serviceName, key)
			}
		}
		if err := validateRestrictedComposePorts(serviceName, serviceDef["ports"]); err != nil { return err }
		if err := validateRestrictedComposeExtraHosts(serviceName, serviceDef["extra_hosts"]); err != nil { return err }
		if labels := serviceDef["labels"]; labels != nil {
			if err := validateRestrictedComposeLabels(serviceName, labels); err != nil { return err }
		}
	}
	return nil
}

func validateRestrictedComposePorts(serviceName string, raw any) error {
	if raw == nil { return nil }
	items, ok := raw.([]any)
	if !ok { return fmt.Errorf("service %s: ports must be a list", serviceName) }
	for _, item := range items {
		switch value := item.(type) {
		case string:
			published := composePublishedPort(value)
			if published > 0 && published < 1024 {
				return fmt.Errorf("service %s: publishing privileged host port %d is administrator-only", serviceName, published)
			}
		case map[string]any:
			published := intValue(value["published"])
			if published > 0 && published < 1024 {
				return fmt.Errorf("service %s: publishing privileged host port %d is administrator-only", serviceName, published)
			}
		default:
			return fmt.Errorf("service %s: invalid port definition", serviceName)
		}
	}
	return nil
}

func composePublishedPort(value string) int {
	// Strip protocol and IPv6/host-IP prefixes. The published host port is the
	// penultimate numeric component in the common short forms HOST:CONTAINER and
	// IP:HOST:CONTAINER. Ranges are conservatively checked at their first value.
	value = strings.TrimSpace(strings.SplitN(value, "/", 2)[0])
	parts := strings.Split(value, ":")
	if len(parts) < 2 { return 0 }
	candidate := strings.TrimSpace(parts[len(parts)-2])
	if dash := strings.Index(candidate, "-"); dash >= 0 { candidate = candidate[:dash] }
	port, _ := strconv.Atoi(candidate)
	return port
}

func intValue(raw any) int {
	switch value := raw.(type) {
	case int: return value
	case int64: return int(value)
	case uint64: return int(value)
	case float64: return int(value)
	case string:
		part := value
		if dash := strings.Index(part, "-"); dash >= 0 { part = part[:dash] }
		parsed, _ := strconv.Atoi(strings.TrimSpace(part))
		return parsed
	default: return 0
	}
}

func validateRestrictedComposeExtraHosts(serviceName string, raw any) error {
	if raw == nil { return nil }
	containsHostGateway := func(value string) bool { return strings.Contains(strings.ToLower(value), "host-gateway") }
	switch value := raw.(type) {
	case []any:
		for _, item := range value {
			if containsHostGateway(fmt.Sprint(item)) {
				return fmt.Errorf("service %s: host-gateway mappings are administrator-only", serviceName)
			}
		}
	case map[string]any:
		for host, target := range value {
			if containsHostGateway(host) || containsHostGateway(fmt.Sprint(target)) {
				return fmt.Errorf("service %s: host-gateway mappings are administrator-only", serviceName)
			}
		}
	default:
		return fmt.Errorf("service %s: invalid extra_hosts definition", serviceName)
	}
	return nil
}

func validateRestrictedComposeLabels(serviceName string, raw any) error {
	check := func(label string) error {
		key := strings.TrimSpace(strings.SplitN(label, "=", 2)[0])
		if isReservedDockerLabel(key) { return fmt.Errorf("service %s: Docker label %q is reserved", serviceName, key) }
		return nil
	}
	switch value := raw.(type) {
	case []any:
		for _, item := range value { if err := check(fmt.Sprint(item)); err != nil { return err } }
	case map[string]any:
		for key := range value { if err := check(key); err != nil { return err } }
	default:
		return fmt.Errorf("service %s: invalid labels definition", serviceName)
	}
	return nil
}

func isReservedDockerLabel(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.HasPrefix(key, "com.docker.compose.") || strings.HasPrefix(key, "io.1panel.") || strings.HasPrefix(key, "1panel.")
}

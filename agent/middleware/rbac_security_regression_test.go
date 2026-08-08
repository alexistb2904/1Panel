package middleware

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
)

func TestContainerAllowedDoesNotTreatOwnedNameAsIDPrefix(t *testing.T) {
	allowed := map[string]struct{}{"deadbeefdead": {}}
	if containerAllowed(allowed, "deadbeefdead0123456789abcdef", "victim") {
		t.Fatal("a crafted 12-character owned container name must never authorize another container by ID prefix")
	}
}

func TestStructuredRBACResourceTransportPreservesDelimiters(t *testing.T) {
	want := []string{"mysql:primary:db,with,commas", "website:api"}
	raw, err := json.Marshal(want)
	if err != nil { t.Fatal(err) }
	header := "b64:" + base64.RawURLEncoding.EncodeToString(raw)
	got := parseRBACStringIDs(header)
	if len(got) != len(want) { t.Fatalf("unexpected decoded resource count: %#v", got) }
	for i := range want { if got[i] != want[i] { t.Fatalf("resource %d mismatch: got %q want %q", i, got[i], want[i]) } }
}

func TestRestrictedContainerRejectsReservedPlatformLabels(t *testing.T) {
	req := dto.ContainerOperate{Labels: []string{"com.docker.compose.project=victim"}}
	if err := validateRestrictedContainerSecurityExtras(req); err == nil {
		t.Fatal("scoped containers must not forge Compose/platform ownership labels")
	}
}

func TestRestrictedComposeRejectsPrivilegedHostPort(t *testing.T) {
	compose := `services:
  web:
    image: nginx:alpine
    ports:
      - "443:8443"
`
	if err := validateRestrictedComposeExtraPolicy(compose); err == nil {
		t.Fatal("scoped Compose must not publish privileged host ports")
	}
}

func TestRestrictedComposeAllowsUnprivilegedHostPort(t *testing.T) {
	compose := `services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
`
	if err := validateRestrictedComposeExtraPolicy(compose); err != nil {
		t.Fatalf("ordinary unprivileged application port should remain available: %v", err)
	}
}

func TestRestrictedComposeRejectsHostGatewayAndInclude(t *testing.T) {
	for name, compose := range map[string]string{
		"host-gateway": `services:
  web:
    image: nginx:alpine
    extra_hosts:
      - "host.docker.internal:host-gateway"
`,
		"include": `include:
  - /etc/compose/production.yaml
services:
  web:
    image: nginx:alpine
`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRestrictedComposeExtraPolicy(compose); err == nil { t.Fatalf("%s must be rejected", name) }
		})
	}
}

func TestRestrictedComposeRejectsReservedLabels(t *testing.T) {
	compose := `services:
  web:
    image: nginx:alpine
    labels:
      com.docker.compose.project: victim
`
	if err := validateRestrictedComposeExtraPolicy(compose); err == nil {
		t.Fatal("scoped Compose must not forge reserved ownership labels")
	}
}

func TestRestrictedWebsiteCreationHasNoImplicitCrossResourceSideEffects(t *testing.T) {
	cases := []map[string]any{
		{"createDb": true},
		{"ftpUser": "shared-user"},
		{"enableSSL": true},
		{"appID": float64(1)},
		{"runtimeID": float64(1)},
	}
	for _, payload := range cases {
		if err := validateRestrictedWebsiteCreation(payload); err == nil {
			t.Fatalf("unsafe website creation side effect must be rejected: %#v", payload)
		}
	}
	if err := validateRestrictedWebsiteCreation(map[string]any{}); err != nil {
		t.Fatalf("plain side-effect-free website creation should remain allowed: %v", err)
	}
}

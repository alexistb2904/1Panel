package middleware

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/model"
)

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
	if err := validateRestrictedContainerSecurityExtras(req); err == nil { t.Fatal("scoped containers must not forge Compose/platform ownership labels") }
}

func TestRestrictedComposeRejectsPrivilegedHostPort(t *testing.T) {
	compose := `services:
  web:
    image: nginx:alpine
    ports:
      - "443:8443"
`
	if err := validateRestrictedComposeExtraPolicy(compose); err == nil { t.Fatal("scoped Compose must not publish privileged host ports") }
}

func TestRestrictedComposeAllowsUnprivilegedHostPort(t *testing.T) {
	compose := `services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
`
	if err := validateRestrictedComposeExtraPolicy(compose); err != nil { t.Fatalf("ordinary unprivileged application port should remain available: %v", err) }
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
	if err := validateRestrictedComposeExtraPolicy(compose); err == nil { t.Fatal("scoped Compose must not forge reserved ownership labels") }
}

func TestRestrictedWebsiteCreationHasNoImplicitCrossResourceSideEffects(t *testing.T) {
	cases := []map[string]any{
		{"createDb": true}, {"ftpUser": "shared-user"}, {"enableSSL": true}, {"appID": float64(1)}, {"runtimeID": float64(1)},
	}
	for _, payload := range cases {
		if err := validateRestrictedWebsiteCreation(payload); err == nil { t.Fatalf("unsafe website creation side effect must be rejected: %#v", payload) }
	}
	if err := validateRestrictedWebsiteCreation(map[string]any{}); err != nil { t.Fatalf("plain side-effect-free website creation should remain allowed: %v", err) }
}

func TestScopedWebsiteTLSViewRedactsPrivateMaterial(t *testing.T) {
	ssl := model.WebsiteSSL{
		PrivateKey: "PRIVATE", Pem: "CERT", CertURL: "secret-url", DnsAccountID: 7, AcmeAccountID: 8, CaID: 9,
		Dir: "/secret", Shell: "curl token", ExecShell: true, Nodes: "all", PrivateKeyPath: "/keys/key.pem", CertPath: "/keys/cert.pem",
		AcmeAccount: model.WebsiteAcmeAccount{Email: "ops@example.com", EabKid: "kid", EabHmacKey: "hmac"},
		DnsAccount: model.WebsiteDnsAccount{Name: "cloud", Type: "provider"},
		Websites: []model.Website{{Alias: "other-site"}},
	}
	redactWebsiteHTTPSForRBAC(&ssl)
	if ssl.PrivateKey != "" || ssl.Pem != "" || ssl.CertURL != "" || ssl.Shell != "" || ssl.PrivateKeyPath != "" || ssl.CertPath != "" {
		t.Fatal("TLS private material/path metadata survived scoped redaction")
	}
	if ssl.DnsAccountID != 0 || ssl.AcmeAccountID != 0 || ssl.CaID != 0 || ssl.ExecShell || len(ssl.Websites) != 0 {
		t.Fatal("TLS account/cross-resource metadata survived scoped redaction")
	}
	if ssl.AcmeAccount.ID != 0 || ssl.DnsAccount.ID != 0 { t.Fatal("nested TLS account objects survived redaction") }
}

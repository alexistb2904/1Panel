package rbac

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSplitServiceToken(t *testing.T) {
	keyID, secret, ok := splitServiceToken("1ps_0123456789abcdef_0123456789abcdef0123456789abcdef")
	if !ok {
		t.Fatal("expected valid service token")
	}
	if keyID != "0123456789abcdef" || secret != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected token split: %s / %s", keyID, secret)
	}
	if _, _, ok := splitServiceToken("1ps_short_secret"); ok {
		t.Fatal("short token must be rejected")
	}
}

func TestServiceAccountIPAllowed(t *testing.T) {
	cases := []struct {
		ip, allow string
		want      bool
	}{
		{"203.0.113.8", "", true},
		{"203.0.113.8", "203.0.113.8", true},
		{"203.0.113.8", "203.0.113.0/24", true},
		{"203.0.114.8", "203.0.113.0/24", false},
		{"10.0.0.8", "192.0.2.10, 10.0.0.0/8", true},
	}
	for _, tc := range cases {
		if got := serviceAccountIPAllowed(tc.ip, tc.allow); got != tc.want {
			t.Fatalf("ip=%s allow=%q got=%v want=%v", tc.ip, tc.allow, got, tc.want)
		}
	}
}

func testServiceIPContext(remoteAddr string, headers map[string]string) *gin.Context {
	req := httptest.NewRequest("GET", "/api/v2/websites/list", nil)
	req.RemoteAddr = remoteAddr
	for key, value := range headers { req.Header.Set(key, value) }
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	return c
}

func TestServiceAccountClientIPIgnoresSpoofedForwardingFromUntrustedPeer(t *testing.T) {
	c := testServiceIPContext("198.51.100.20:54321", map[string]string{"X-Forwarded-For": "10.0.0.15", "X-Real-IP": "10.0.0.15"})
	got := serviceAccountClientIPWithTrustedProxies(c, "10.0.0.0/8")
	if got != "198.51.100.20" { t.Fatalf("untrusted peer spoofed forwarding headers: got %s", got) }
}

func TestServiceAccountClientIPAcceptsForwardingFromTrustedPeer(t *testing.T) {
	c := testServiceIPContext("10.0.0.2:443", map[string]string{"X-Forwarded-For": "203.0.113.9, 10.0.0.3"})
	got := serviceAccountClientIPWithTrustedProxies(c, "10.0.0.0/8")
	if got != "203.0.113.9" { t.Fatalf("expected original client IP, got %s", got) }
}

func TestServiceAccountClientIPWalksTrustedProxyChainRightToLeft(t *testing.T) {
	c := testServiceIPContext("10.0.0.2:443", map[string]string{"X-Forwarded-For": "198.51.100.7, 192.0.2.20, 10.0.0.3"})
	got := serviceAccountClientIPWithTrustedProxies(c, "10.0.0.0/8;192.0.2.0/24")
	if got != "198.51.100.7" { t.Fatalf("expected first untrusted client hop, got %s", got) }
}

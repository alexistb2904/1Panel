package rbac

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func nodeContext(rawURL string, headers map[string]string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("GET", rawURL, nil)
	for key, value := range headers { req.Header.Set(key, value) }
	c.Request = req
	return c
}

func TestResolveRequestNodeSelectorRejectsConflictingSelectors(t *testing.T) {
	c := nodeContext("/api/v2/websites/list?operateNode=node-a", map[string]string{"CurrentNode": "node-b"})
	if _, err := ResolveRequestNodeSelector(c); err == nil {
		t.Fatal("conflicting operateNode and CurrentNode must be rejected")
	}
}

func TestResolveRequestNodeSelectorUsesXPanelHeader(t *testing.T) {
	c := nodeContext("/api/v2/websites/list", map[string]string{"X-Panel-Current-Node": "node-production"})
	got, err := ResolveRequestNodeSelector(c)
	if err != nil { t.Fatal(err) }
	if got != "node-production" { t.Fatalf("unexpected selector %q", got) }
}

func TestResolveRequestNodeSelectorNormalizesLocalAliases(t *testing.T) {
	for _, value := range []string{"", "local", "master", "0"} {
		c := nodeContext("/api/v2/websites/list", map[string]string{"CurrentNode": value})
		got, err := ResolveRequestNodeSelector(c)
		if err != nil { t.Fatal(err) }
		if got != "local" { t.Fatalf("value %q should resolve to local, got %q", value, got) }
	}
}

func TestResolveRequestNodeSelectorAcceptsEquivalentLocalSelectors(t *testing.T) {
	c := nodeContext("/api/v2/websites/list?operateNode=master", map[string]string{"CurrentNode": "0", "X-Panel-Current-Node": "local"})
	got, err := ResolveRequestNodeSelector(c)
	if err != nil { t.Fatal(err) }
	if got != "local" { t.Fatalf("equivalent local aliases must agree, got %q", got) }
}

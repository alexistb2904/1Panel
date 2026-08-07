package router

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestIsProxyAPIRequestAcceptsScopedServiceAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	c.Set("SCOPED_API_AUTH", true)
	if !isProxyAPIRequest(c) {
		t.Fatal("scoped service account authentication must bypass browser session checks in the proxy")
	}
}

func TestIsProxyAPIRequestRejectsUnauthenticatedContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	if isProxyAPIRequest(c) {
		t.Fatal("unauthenticated context must not be treated as API-authenticated")
	}
}

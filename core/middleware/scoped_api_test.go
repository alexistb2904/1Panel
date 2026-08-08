package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/core/constant"
	"github.com/gin-gonic/gin"
)

const testScopedServiceToken = "1ps_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestScopedServiceTokenShapeIsExact(t *testing.T) {
	if !IsScopedServiceTokenRequestAuthorization("Bearer " + testScopedServiceToken) {
		t.Fatal("generated service token shape must be recognized before session-only middleware")
	}
	for _, value := range []string{
		"Basic " + testScopedServiceToken,
		"Bearer 1ps_0123456789abcdef_short",
		"Bearer 1ps_0123456789ABCDEF_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"Bearer " + testScopedServiceToken + " trailing",
		"Bearer 1ps_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
	} {
		if IsScopedServiceTokenRequestAuthorization(value) {
			t.Fatalf("malformed service token header was classified as scoped: %q", value)
		}
	}
}

func TestPasswordExpiredDoesNotRequireBrowserSessionForScopedToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	reached := false
	router.Use(PasswordExpired())
	router.POST("/api/v2/websites/update", func(c *gin.Context) {
		reached = true
		c.Status(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v2/websites/update", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testScopedServiceToken)
	router.ServeHTTP(recorder, req)
	if !reached {
		t.Fatalf("scoped service token was rejected by browser password middleware: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCSRFDoesNotTreatScopedTokenWithStaleCookieAsBrowserSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/websites/update", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testScopedServiceToken)
	req.AddCookie(&http.Cookie{Name: constant.SessionName, Value: "stale-browser-session"})
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req
	if requiresCSRFTokenCheck(ctx) {
		t.Fatal("machine principal must not be forced through browser CSRF validation because of a stale cookie")
	}
}

func TestOrdinaryUnsafeSessionRequestStillRequiresCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/websites/update", strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: constant.SessionName, Value: "browser-session"})
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req
	if !requiresCSRFTokenCheck(ctx) {
		t.Fatal("ordinary browser session unexpectedly bypassed CSRF validation")
	}
}

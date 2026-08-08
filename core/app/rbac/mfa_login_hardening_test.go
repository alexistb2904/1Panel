package rbac

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	initauth "github.com/1Panel-dev/1Panel/core/init/auth"
	"github.com/gin-gonic/gin"
)

func TestCommunityMFASessionHasBoundedAttemptBudget(t *testing.T) {
	db := withAuthHardeningDB(t)
	withGlobalDB(t, db)
	gin.SetMode(gin.TestMode)
	store := initauth.GetMFASessionStore()
	sessionID := store.SetWithAuthSource("user", "", "127.0.0.1", "community", 1, 0)
	defer store.Delete(sessionID)

	reached := 0
	router := gin.New()
	router.POST("/mfa", RequireCommunityMFASessionAfterRBAC(), func(c *gin.Context) {
		reached++
		c.JSON(http.StatusUnauthorized, gin.H{"code": http.StatusUnauthorized})
	})
	body := fmt.Sprintf(`{"sessionID":%q,"code":"000000"}`, sessionID)
	// fmt %q already quotes and escapes a JSON-safe ASCII session identifier;
	// remove the raw-string escaping around the field names to produce the real
	// wire payload used by the API.
	body = fmt.Sprintf("{\"sessionID\":%q,\"code\":\"000000\"}", sessionID)
	for i := 0; i < initauth.MFASessionMaxFailures+1; i++ {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, req)
	}
	if reached != initauth.MFASessionMaxFailures {
		t.Fatalf("MFA handler reached %d times, want exactly %d", reached, initauth.MFASessionMaxFailures)
	}
	if _, ok := store.Get(sessionID); ok {
		t.Fatal("MFA session must be invalidated when attempt budget is exhausted")
	}
}

func TestCommunityMFASessionIsSerializedAsOneTimeCredential(t *testing.T) {
	db := withAuthHardeningDB(t)
	withGlobalDB(t, db)
	gin.SetMode(gin.TestMode)
	store := initauth.GetMFASessionStore()
	sessionID := store.SetWithAuthSource("user", "", "127.0.0.1", "community", 1, 0)
	defer store.Delete(sessionID)

	reached := 0
	var reachedMu sync.Mutex
	router := gin.New()
	router.POST("/mfa", RequireCommunityMFASessionAfterRBAC(), func(c *gin.Context) {
		reachedMu.Lock()
		reached++
		reachedMu.Unlock()
		store.Delete(sessionID)
		c.JSON(http.StatusOK, gin.H{"code": http.StatusOK})
	})

	body := fmt.Sprintf("{\"sessionID\":%q,\"code\":\"123456\"}", sessionID)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			<-start
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/mfa", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, req)
		}()
	}
	close(start)
	wg.Wait()
	reachedMu.Lock()
	got := reached
	reachedMu.Unlock()
	if got != 1 {
		t.Fatalf("one-time MFA session reached handler %d times under concurrency, want 1", got)
	}
}

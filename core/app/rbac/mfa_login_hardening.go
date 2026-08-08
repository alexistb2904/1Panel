package rbac

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	initauth "github.com/1Panel-dev/1Panel/core/init/auth"
	"github.com/gin-gonic/gin"
)

type communityMFAGuardEntry struct {
	mu       sync.Mutex
	refs     int
	attempts int
	lastSeen time.Time
	remove   bool
}

var communityMFAGuards = struct {
	sync.Mutex
	items map[string]*communityMFAGuardEntry
}{items: make(map[string]*communityMFAGuardEntry)}

func acquireCommunityMFAGuard(sessionID string) (*communityMFAGuardEntry, func()) {
	now := time.Now()
	communityMFAGuards.Lock()
	for key, item := range communityMFAGuards.items {
		if item.refs == 0 && now.Sub(item.lastSeen) > initauth.MFASessionTTL {
			delete(communityMFAGuards.items, key)
		}
	}
	entry := communityMFAGuards.items[sessionID]
	if entry == nil {
		entry = &communityMFAGuardEntry{lastSeen: now}
		communityMFAGuards.items[sessionID] = entry
	}
	entry.refs++
	communityMFAGuards.Unlock()

	entry.mu.Lock()
	entry.lastSeen = now
	return entry, func() {
		entry.mu.Unlock()
		communityMFAGuards.Lock()
		entry.refs--
		if entry.refs == 0 && entry.remove {
			delete(communityMFAGuards.items, sessionID)
		}
		communityMFAGuards.Unlock()
	}
}

// RequireCommunityMFASessionAfterRBAC prevents a stale legacy single-admin MFA
// session from completing authentication after the multi-user migration. It
// also serializes attempts per MFA session and enforces the same five-attempt
// budget as the legacy MFA store. Without the per-session lock, two concurrent
// valid requests could both observe the one-time session before the handler
// deletes it and both complete authentication.
func RequireCommunityMFASessionAfterRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !CommunityRBACEnabled() {
			c.Next()
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse MFA login request")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		var payload struct {
			SessionID string `json:"sessionID"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || strings.TrimSpace(payload.SessionID) == "" {
			deny(c, http.StatusUnauthorized, "Invalid MFA session")
			return
		}
		sessionID := strings.TrimSpace(payload.SessionID)
		entry, release := acquireCommunityMFAGuard(sessionID)
		defer release()

		session, ok := initauth.GetMFASessionStore().Get(sessionID)
		if !ok || session.AuthSource != "community" {
			entry.remove = true
			deny(c, http.StatusUnauthorized, "Invalid MFA session")
			return
		}
		if entry.attempts >= initauth.MFASessionMaxFailures {
			initauth.GetMFASessionStore().Delete(sessionID)
			entry.remove = true
			deny(c, http.StatusUnauthorized, "Invalid MFA session")
			return
		}
		entry.attempts++
		c.Next()

		// A successful community MFA login consumes the session in auth.go.
		// Removing the guard state here keeps this registry bounded and means a
		// future independently generated session begins with a fresh budget.
		if _, stillExists := initauth.GetMFASessionStore().Get(sessionID); !stillExists {
			entry.remove = true
		}
	}
}

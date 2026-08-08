package rbac

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/app/repo"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const GinContextScopedAPIAuthKey = "SCOPED_API_AUTH"
const GinContextRBACSubjectTypeKey = "rbac_subject_type"

const (
	serviceCredentialLastUsedWriteInterval = time.Minute
	serviceTokenKeyIDLength                 = 16
	serviceTokenSecretLength                = 64
	serviceTokenLength                      = len("1ps_") + serviceTokenKeyIDLength + 1 + serviceTokenSecretLength
	serviceAuthorizationMaxLength           = 256
)

var serviceAccountDummyHash = make([]byte, sha256.Size)

// ServiceAccountAuthMiddleware accepts only the exact token shape emitted by
// Create/RotateServiceAccount: Bearer 1ps_<16 lowercase hex>_<64 lowercase hex>.
// The secret is never stored in plaintext. Authentication failures are
// deliberately indistinguishable to callers so key IDs, expiry state, IP
// policy and account state cannot be enumerated remotely.
func ServiceAccountAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := strings.TrimSpace(c.GetHeader("Authorization"))
		if len(authz) > serviceAuthorizationMaxLength {
			if strings.HasPrefix(strings.ToLower(authz), "bearer 1ps_") {
				denyServiceAccountAuth(c)
				return
			}
			c.Next()
			return
		}
		parts := strings.Fields(authz)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !strings.HasPrefix(parts[1], "1ps_") {
			c.Next()
			return
		}
		keyID, secret, ok := splitServiceToken(parts[1])
		if !ok {
			denyServiceAccountAuth(c)
			return
		}

		provided := sha256.Sum256([]byte(secret))
		var credential model.AccessServiceCredential
		err := global.DB.Where("key_id = ? AND status = ?", keyID, model.AccessUserStatusActive).First(&credential).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Keep the secret-comparison work present for unknown key IDs instead
			// of returning immediately on a distinguishable fast path.
			_ = subtle.ConstantTimeCompare(serviceAccountDummyHash, provided[:])
			denyServiceAccountAuth(c)
			return
		}
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to authenticate service account")
			return
		}

		expected, decodeErr := hex.DecodeString(credential.SecretHash)
		validSecret := decodeErr == nil && len(expected) == sha256.Size && subtle.ConstantTimeCompare(expected, provided[:]) == 1
		now := time.Now()
		validExpiry := credential.ExpiresAt == nil || now.Before(*credential.ExpiresAt)
		clientIP := serviceAccountClientIP(c)
		validIP := serviceAccountIPAllowed(clientIP, credential.IPWhiteList)
		if !validSecret || !validExpiry || !validIP {
			denyServiceAccountAuth(c)
			return
		}

		var user model.AccessUser
		if err := global.DB.Where("id = ? AND auth_source = ? AND status = ?", credential.UserID, "service_account", model.AccessUserStatusActive).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				denyServiceAccountAuth(c)
				return
			}
			deny(c, http.StatusInternalServerError, "Unable to authenticate service account")
			return
		}

		// last_used_at is observability metadata, not part of authorization. Do
		// not turn every valid API call into a database write. A conditional
		// update keeps the timestamp fresh to minute precision and remains safe
		// under concurrent requests without an in-process cache.
		cutoff := now.Add(-serviceCredentialLastUsedWriteInterval)
		_ = global.DB.Model(&model.AccessServiceCredential{}).
			Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", credential.ID, cutoff).
			Update("last_used_at", &now).Error

		c.Set(GinContextAccessUserIDKey, user.ID)
		c.Set(GinContextScopedAPIAuthKey, true)
		c.Set(GinContextRBACSubjectTypeKey, "service_account")
		c.Next()
	}
}

func denyServiceAccountAuth(c *gin.Context) {
	deny(c, http.StatusUnauthorized, "Invalid service account credential")
}

func splitServiceToken(token string) (string, string, bool) {
	if len(token) != serviceTokenLength || !strings.HasPrefix(token, "1ps_") {
		return "", "", false
	}
	payload := strings.TrimPrefix(token, "1ps_")
	if len(payload) != serviceTokenKeyIDLength+1+serviceTokenSecretLength || payload[serviceTokenKeyIDLength] != '_' {
		return "", "", false
	}
	keyID := payload[:serviceTokenKeyIDLength]
	secret := payload[serviceTokenKeyIDLength+1:]
	if !isLowerHexServiceToken(keyID) || !isLowerHexServiceToken(secret) {
		return "", "", false
	}
	return keyID, secret, true
}

func isLowerHexServiceToken(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
			continue
		}
		return false
	}
	return true
}

func directPeerIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return strings.TrimSpace(host)
	}
	return remoteAddr
}

func parseTrustedProxyNetworks(raw string) []*net.IPNet {
	var networks []*net.IPNet
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, network, err := net.ParseCIDR(item); err == nil {
			networks = append(networks, network)
		}
	}
	return networks
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func serviceAccountClientIP(c *gin.Context) string {
	trustedRaw, err := repo.NewISettingRepo().GetValueByKey("ApiTrustedProxies")
	if err != nil {
		trustedRaw = ""
	}
	return serviceAccountClientIPWithTrustedProxies(c, trustedRaw)
}

// serviceAccountClientIPWithTrustedProxies never trusts forwarding headers from
// an arbitrary peer. X-Forwarded-For/X-Real-IP are considered only when the TCP
// peer itself matches the administrator-managed trusted proxy set.
func serviceAccountClientIPWithTrustedProxies(c *gin.Context, trustedRaw string) string {
	peerRaw := directPeerIP(c.Request.RemoteAddr)
	peer := net.ParseIP(peerRaw)
	if peer == nil {
		return peerRaw
	}
	trusted := parseTrustedProxyNetworks(trustedRaw)
	if !ipInNetworks(peer, trusted) {
		return peer.String()
	}

	forwarded := strings.Join(c.Request.Header.Values("X-Forwarded-For"), ",")
	if strings.TrimSpace(forwarded) != "" {
		parts := strings.Split(forwarded, ",")
		var leftmost net.IP
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(parts[i]))
			if candidate == nil {
				continue
			}
			leftmost = candidate
			if !ipInNetworks(candidate, trusted) {
				return candidate.String()
			}
		}
		if leftmost != nil {
			return leftmost.String()
		}
	}
	if realIP := net.ParseIP(strings.TrimSpace(c.GetHeader("X-Real-IP"))); realIP != nil {
		return realIP.String()
	}
	return peer.String()
}

func serviceAccountIPAllowed(clientIP, raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return false
	}
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if candidate := net.ParseIP(item); candidate != nil && candidate.Equal(ip) {
			return true
		}
		if _, network, err := net.ParseCIDR(item); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

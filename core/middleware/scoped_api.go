package middleware

import "strings"

// IsScopedServiceTokenRequest performs only a bounded syntactic classification
// of the Authorization header. It does not authenticate the token. The actual
// credential is still verified fail-closed by RBAC's ServiceAccountAuthMiddleware.
//
// This helper exists because session-only middleware (password expiry and CSRF)
// runs before the RBAC provider in the global chain. A machine principal must
// not be rejected for lacking a browser session before it reaches its real
// authentication middleware.
func IsScopedServiceTokenRequestHeader(authorization string) bool {
	authorization = strings.TrimSpace(authorization)
	if len(authorization) > 256 {
		return false
	}
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	token := parts[1]
	if !strings.HasPrefix(token, "1ps_") || len(token) != 85 {
		return false
	}
	keyID, secret, ok := strings.Cut(strings.TrimPrefix(token, "1ps_"), "_")
	if !ok || len(keyID) != 16 || len(secret) != 64 {
		return false
	}
	return isLowerHex(keyID) && isLowerHex(secret)
}

func IsScopedServiceTokenRequestAuthorization(authorization string) bool {
	return IsScopedServiceTokenRequestHeader(authorization)
}

func isLowerHex(value string) bool {
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

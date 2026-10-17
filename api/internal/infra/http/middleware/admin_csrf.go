package middleware

// The platform console's CSRF token is bound to its session (RFC-022
// revision 21): HMAC-SHA256 under a server key of the session token, never a
// free-standing random value checked as cookie == header. On a second port of
// the tenant host the two sites share the host's cookies, so a script on a
// tenant page could plant an admin_csrf cookie of its own (on a more specific
// path); a session-bound token cannot be forged without the session secret
// and the server key, whatever cookies the browser holds.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
)

const adminCSRFLabel = "openctem-admin-csrf-v1\x00"

var (
	adminCSRFMu  sync.RWMutex
	adminCSRFKey = randomAdminCSRFKey()
)

func randomAdminCSRFKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("admin csrf: no randomness: " + err.Error())
	}
	return k
}

// SetAdminCSRFSecret derives the console CSRF key from a server secret
// shared by every replica (the session-signing secret). Without one, each
// process keeps its own random key: tokens then verify only on the process
// that issued them (single replica).
func SetAdminCSRFSecret(secret string) {
	if secret == "" {
		return
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(adminCSRFLabel))
	adminCSRFMu.Lock()
	adminCSRFKey = mac.Sum(nil)
	adminCSRFMu.Unlock()
}

// AdminCSRFToken is the CSRF token of the console session sessionToken.
func AdminCSRFToken(sessionToken string) string {
	adminCSRFMu.RLock()
	mac := hmac.New(sha256.New, adminCSRFKey)
	adminCSRFMu.RUnlock()
	mac.Write([]byte(adminCSRFLabel))
	mac.Write([]byte(sessionToken))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ValidAdminCSRF reports, in constant time, whether header is the CSRF token
// of the console session sessionToken.
func ValidAdminCSRF(sessionToken, header string) bool {
	if sessionToken == "" || header == "" {
		return false
	}
	return hmac.Equal([]byte(AdminCSRFToken(sessionToken)), []byte(header))
}

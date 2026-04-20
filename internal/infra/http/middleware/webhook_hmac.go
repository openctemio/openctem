package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// F-1 / F-314: Generic HMAC-SHA256 verification middleware for public webhook
// endpoints. Protects against tenant spoofing + payload forgery on endpoints
// that cannot use JWT auth (because the caller is an external provider).
//
// The middleware:
//  1. Reads the entire request body (bounded by maxBytes) and re-attaches it
//     so downstream handlers can still decode it.
//  2. Computes HMAC-SHA256(body, secret) and constant-time-compares against
//     the value in the configured header.
//  3. Rejects with 401 on missing / malformed / mismatched signature.
//
// Accepted header formats (first match wins):
//   - hex                   ->  "abcdef0123..."
//   - "sha256=" + hex       ->  "sha256=abcdef..."  (GitHub/Jira style)
//
// Secret resolution is pluggable via secretFn — allows per-integration lookup
// in the future. For now callers typically pass a closure returning a single
// platform-wide secret.

const webhookMaxBody = 2 * 1024 * 1024 // 2 MiB — tighter than the default.

// WebhookSecretFn returns the HMAC secret used to verify an incoming request.
// It receives the request so implementations can derive the secret per-tenant,
// per-integration, or per-path. Return ("", false) to reject.
type WebhookSecretFn func(r *http.Request) (secret string, ok bool)

// VerifyHMAC returns middleware that enforces HMAC-SHA256 on the request body.
// headerName is the header that carries the signature (e.g. "X-OpenCTEM-Signature").
// If the resolved secret is empty, the middleware refuses all requests — this
// is intentional to prevent silent bypass when configuration is missing.
func VerifyHMAC(headerName string, secretFn WebhookSecretFn, log *logger.Logger) func(http.Handler) http.Handler {
	if headerName == "" {
		headerName = "X-OpenCTEM-Signature"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sigHeader := r.Header.Get(headerName)
			if sigHeader == "" {
				log.Warn("webhook rejected: missing signature", "header", headerName, "path", r.URL.Path, "remote_ip", r.RemoteAddr)
				apierror.Unauthorized("missing webhook signature").WriteJSON(w)
				return
			}

			secret, ok := secretFn(r)
			if !ok || secret == "" {
				// Fail closed — do not process an unsigned-equivalent request.
				log.Error("webhook rejected: no secret configured", "path", r.URL.Path)
				apierror.Unauthorized("webhook not configured").WriteJSON(w)
				return
			}

			// Body is bounded — very large payloads are rejected before HMAC work.
			body, err := io.ReadAll(io.LimitReader(r.Body, webhookMaxBody+1))
			if err != nil {
				log.Warn("webhook rejected: body read failed", "path", r.URL.Path, "error", err)
				apierror.BadRequest("invalid request body").WriteJSON(w)
				return
			}
			if len(body) > webhookMaxBody {
				log.Warn("webhook rejected: body too large", "path", r.URL.Path, "bytes", len(body))
				apierror.BadRequest("request body too large").WriteJSON(w)
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))

			expected := computeHMAC(body, secret)
			provided := normalizeSig(sigHeader)
			if provided == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
				log.Warn("webhook rejected: bad signature", "path", r.URL.Path, "remote_ip", r.RemoteAddr)
				apierror.Unauthorized("invalid webhook signature").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// computeHMAC returns the lowercase-hex HMAC-SHA256 of body keyed with secret.
func computeHMAC(body []byte, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// normalizeSig accepts either raw hex ("ab12...") or "sha256=ab12..." and
// returns the lowercase hex portion. Returns "" on malformed input.
func normalizeSig(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "sha256=")
	h = strings.ToLower(h)
	if _, err := hex.DecodeString(h); err != nil {
		return ""
	}
	return h
}

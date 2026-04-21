package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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

const (
	webhookMaxBody = 2 * 1024 * 1024 // 2 MiB — tighter than the default.
	// webhookTimestampTolerance bounds replay attacks: a captured
	// signature is only valid for ±5 minutes. 5 min is the industry
	// standard (Stripe, GitHub use the same window) — long enough to
	// absorb clock skew between sender and us, short enough that a
	// captured signature from yesterday's logs is useless.
	webhookTimestampTolerance = 5 * time.Minute
	webhookTimestampHeader    = "X-OpenCTEM-Timestamp"
)

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

			// Replay protection: require a recent timestamp header.
			// HMAC alone protects against forgery but NOT replay — an
			// attacker who captured a valid signed request once could
			// resend it indefinitely. Including the timestamp in the
			// HMAC input + bounding it to ±5 minutes turns a replay
			// into either a clock-skew rejection or a stale-window
			// rejection. Senders MUST include this header (Stripe-style
			// "t=<unix>,v1=<sig>" can also be parsed but plain header
			// is simpler for first iteration).
			tsHeader := r.Header.Get(webhookTimestampHeader)
			if tsHeader == "" {
				log.Warn("webhook rejected: missing timestamp", "path", r.URL.Path)
				apierror.Unauthorized("missing webhook timestamp header (X-OpenCTEM-Timestamp)").WriteJSON(w)
				return
			}
			tsUnix, err := strconv.ParseInt(strings.TrimSpace(tsHeader), 10, 64)
			if err != nil {
				log.Warn("webhook rejected: invalid timestamp", "path", r.URL.Path, "ts", tsHeader)
				apierror.Unauthorized("invalid webhook timestamp").WriteJSON(w)
				return
			}
			ts := time.Unix(tsUnix, 0)
			delta := time.Since(ts)
			if delta < 0 {
				delta = -delta
			}
			if delta > webhookTimestampTolerance {
				log.Warn("webhook rejected: timestamp outside tolerance",
					"path", r.URL.Path, "delta_seconds", delta.Seconds())
				apierror.Unauthorized("webhook timestamp outside tolerance window").WriteJSON(w)
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

			// Compute HMAC over (timestamp + "." + body) — the timestamp
			// MUST be in the signed payload, otherwise an attacker could
			// strip the timestamp header and replace it with a fresh one
			// while keeping the original body+signature.
			expected := computeHMACWithTimestamp(body, tsHeader, secret)
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
// Kept for backward compatibility with senders that haven't been
// upgraded to the timestamp variant — new code should use
// computeHMACWithTimestamp.
func computeHMAC(body []byte, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// computeHMACWithTimestamp signs (timestamp + "." + body). Including
// the timestamp in the signed payload is what makes the timestamp
// header tamper-evident — without this binding, an attacker could
// strip+replace the timestamp header to bypass the freshness window.
// Format is "<ts>.<body>" (Stripe convention).
func computeHMACWithTimestamp(body []byte, ts, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(ts))
	_, _ = m.Write([]byte("."))
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

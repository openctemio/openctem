package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// AuditActionWriteStarted is the write-ahead row of a super administrator's
// write: written before the handler runs, so the attempt is on record even if
// the outcome row (written after the response) is lost.
const AuditActionWriteStarted = "admin.write_started"

// CodeAuditUnavailable is the refusal when the write-ahead row cannot be stored.
const CodeAuditUnavailable apierror.Code = "AUDIT_UNAVAILABLE"

// writeAheadBodyLimit caps the request body read for the write-ahead row.
const writeAheadBodyLimit = 1024 * 1024

// WriteAhead returns middleware for the console's authenticated chain, after
// Authenticate. For a state-changing request whose acting role is super_admin
// it writes one audit row synchronously (request context, auditWriteTimeout)
// before the handler runs; when the row cannot be written the request is
// refused with 503 AUDIT_UNAVAILABLE and the handler is not called. Reads and
// the writes of other roles pass unchanged (their outcome rows stay
// best-effort).
func (m *AuditMiddleware) WriteAhead() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !writeAheadApplies(r) {
				next.ServeHTTP(w, r)
				return
			}

			var body map[string]interface{}
			if r.Body != nil && r.ContentLength > 0 && r.ContentLength < writeAheadBodyLimit {
				if raw, err := io.ReadAll(r.Body); err == nil {
					r.Body = io.NopCloser(bytes.NewBuffer(raw))
					_ = json.Unmarshal(raw, &body)
				}
			}
			entry := admin.NewAuditLogBuilder(GetAdminUser(r.Context()), AuditActionWriteStarted).
				Context(extractIP(r), r.UserAgent()).
				Request(r.Method, r.URL.Path, body).
				Build()

			ctx, cancel := context.WithTimeout(r.Context(), auditWriteTimeout)
			defer cancel()
			if err := m.auditRepo.Create(ctx, entry); err != nil {
				m.logger.Error("admin write-ahead audit failed; write refused",
					"error", err, "method", r.Method, "path", logSafe(r.URL.Path))
				apierror.New(http.StatusServiceUnavailable, CodeAuditUnavailable,
					"The administrators' audit log cannot be written; the change was not made.").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeAheadApplies(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return GetAdminRole(r.Context()) == string(admin.AdminRoleSuperAdmin)
}

// logSafe strips CR/LF from a request-controlled value before it is logged.
func logSafe(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

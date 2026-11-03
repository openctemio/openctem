package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

func requestLogLine(t *testing.T, inner http.HandlerFunc) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	log := logger.New(logger.Config{Level: "info", Format: "json", Output: &buf})
	h := LoggerWithConfig(log, LoggerConfig{})(inner)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/assets/x", nil))
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &m); err != nil {
		t.Fatalf("request log is not one JSON line: %q", buf.String())
	}
	return m
}

// A request refused after authentication (403) names who was refused, so an
// access-control failure can be attributed and counted per user and tenant.
func TestRequestLog_NamesAuthenticatedPrincipalOnRefusal(t *testing.T) {
	m := requestLogLine(t, func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), UserIDKey, "user-1")
		ctx = context.WithValue(ctx, TenantIDKey, "tenant-1")
		ctx = context.WithValue(ctx, EmailKey, "person@example.test")
		notePrincipal(ctx)
		w.WriteHeader(http.StatusForbidden)
	})
	if m["status"] != float64(http.StatusForbidden) || m["level"] != "WARN" {
		t.Fatalf("status/level = %v/%v", m["status"], m["level"])
	}
	if m["user_id"] != "user-1" || m["tenant_id"] != "tenant-1" {
		t.Fatalf("principal = user:%v tenant:%v", m["user_id"], m["tenant_id"])
	}
	for k, v := range m {
		if s, ok := v.(string); ok && strings.Contains(s, "@") {
			t.Fatalf("request log field %s carries an e-mail: %q", k, s)
		}
	}
}

// Unauthenticated requests log no principal; a platform administrator is
// logged as admin_id, not as a tenant user.
func TestRequestLog_PrincipalAbsentOrAdmin(t *testing.T) {
	m := requestLogLine(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	for _, k := range []string{"user_id", "tenant_id", "admin_id"} {
		if _, ok := m[k]; ok {
			t.Fatalf("unauthenticated request logged %s", k)
		}
	}
	m = requestLogLine(t, func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), UserIDKey, "admin-1")
		noteAdminPrincipal(ctx, "admin-1")
		notePrincipal(ctx)
		w.WriteHeader(http.StatusOK)
	})
	if m["admin_id"] != "admin-1" {
		t.Fatalf("admin_id = %v", m["admin_id"])
	}
	if _, ok := m["user_id"]; ok {
		t.Fatal("platform administrator also logged as user_id")
	}
}

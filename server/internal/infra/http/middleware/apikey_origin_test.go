package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The origin the scan approval rules read is set by the authenticator,
// not by the request: the MCP endpoint is mcp, the REST API api_key, and
// no request header changes it.
func TestAPIKeyAuth_RecordsOrigin(t *testing.T) {
	fa := &fakeAuthenticator{key: newTestKey(shared.NewID(), []string{"scans:read"})}
	m := NewAPIKeyAuth(fa, logger.NewNop())
	var got scangov.Origin
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = scangov.OriginFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	cases := []struct {
		name string
		h    http.Handler
		path string
		want scangov.Origin
	}{
		{"mcp endpoint", m.Handler(capture), "/api/v1/mcp", scangov.OriginMCP},
		{"rest api", m.OrJWT(func(next http.Handler) http.Handler { return next })(capture), "/api/v1/scans", scangov.OriginAPIKey},
	}
	for _, c := range cases {
		got = ""
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		req.Header.Set("Authorization", "Bearer oct_secret123")
		req.Header.Set("X-Origin", "ui")
		rec := httptest.NewRecorder()
		c.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || got != c.want {
			t.Errorf("%s: status %d origin %q, want %q", c.name, rec.Code, got, c.want)
		}
	}
}

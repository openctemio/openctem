package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// Login CSRF on the routes that run before a session exists: a write a
// browser sends on behalf of another site is refused; the web console's
// server-side calls (no Origin, no Sec-Fetch-Site) and same-origin browser
// calls pass.
func TestRejectCrossSiteBrowser(t *testing.T) {
	mw := RejectCrossSiteBrowser([]string{"https://app.example.com"}, logger.NewNop())
	reached := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, tc := range []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"server-to-server (web console server, curl, seed)", http.MethodPost, nil, http.StatusNoContent},
		{"same-origin browser", http.MethodPost, map[string]string{"Origin": "https://api.example.com", "Sec-Fetch-Site": "same-origin"}, http.StatusNoContent},
		{"gateway-forwarded host", http.MethodPost, map[string]string{"Origin": "https://console.example.net", "X-Forwarded-Host": "console.example.net"}, http.StatusNoContent},
		{"allowed browser origin (CORS)", http.MethodPost, map[string]string{"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site"}, http.StatusNoContent},
		{"user-initiated, no Origin", http.MethodPost, map[string]string{"Sec-Fetch-Site": "none"}, http.StatusNoContent},
		{"foreign Origin", http.MethodPost, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"foreign Origin on PUT", http.MethodPut, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"foreign Origin on DELETE", http.MethodDelete, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"sibling subdomain not allowed", http.MethodPost, map[string]string{"Origin": "https://x.example.com", "Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"opaque Origin", http.MethodPost, map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"malformed Origin", http.MethodPost, map[string]string{"Origin": "::"}, http.StatusForbidden},
		{"cross-site without Origin", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"GET is not checked", http.MethodGet, map[string]string{"Origin": "https://evil.example"}, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(tc.method, "https://api.example.com/api/v1/auth/login", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if reached != (tc.want == http.StatusNoContent) {
				t.Fatalf("handler reached = %v, want %v", reached, !reached)
			}
		})
	}
}

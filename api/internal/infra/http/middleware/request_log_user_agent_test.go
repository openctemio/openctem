package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestLogger_RecordsUserAgent(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New(logger.Config{Level: "info", Format: "json", Output: &buf})
	h := Logger(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	req.Header.Set("User-Agent", "openctemio-sensor/0.3.1 openctem-sdk-go/0.7.4")
	h.ServeHTTP(httptest.NewRecorder(), req)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v: %q", err, buf.String())
	}
	if got := entry["user_agent"]; got != "openctemio-sensor/0.3.1 openctem-sdk-go/0.7.4" {
		t.Errorf("user_agent = %v, want the request's User-Agent", got)
	}
}

// The request log carries the resolved client address next to the TCP peer,
// so an operator (and the self-hosting kit's monitor) can check what the
// audit log and the per-address limits see behind the gateway.
func TestLogger_RecordsResolvedClientIP(t *testing.T) {
	prev := trustedProxies
	t.Cleanup(func() { SetTrustedProxies(prev) })
	SetTrustedProxies(httpsec.NewTrustedProxySet([]string{"10.0.0.10"}))

	for _, tt := range []struct{ name, remote, xff, want string }{
		{"from the gateway", "10.0.0.10:4000", "203.0.113.7", "203.0.113.7"},
		{"forged by an untrusted peer", "198.51.100.3:4000", "203.0.113.7", "198.51.100.3"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := logger.New(logger.Config{Level: "info", Format: "json", Output: &buf})
			h := Logger(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v2/sensor/hello", nil)
			req.RemoteAddr = tt.remote
			req.Header.Set("X-Forwarded-For", tt.xff)
			h.ServeHTTP(httptest.NewRecorder(), req)
			var entry map[string]any
			if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
				t.Fatalf("log line is not JSON: %v: %q", err, buf.String())
			}
			if got := entry["client_ip"]; got != tt.want {
				t.Errorf("client_ip = %v, want %s", got, tt.want)
			}
		})
	}
}

func TestLogUserAgent(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"agent era", "sdk/1.0", "sdk/1.0"},
		{"line breaks removed", "evil\r\nlevel=ERROR msg=forged", "evillevel=ERROR msg=forged"},
		{"bounded", strings.Repeat("a", 500), strings.Repeat("a", maxLoggedUserAgent)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logUserAgent(tt.in); got != tt.want {
				t.Errorf("logUserAgent(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

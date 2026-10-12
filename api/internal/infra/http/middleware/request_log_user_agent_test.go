package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

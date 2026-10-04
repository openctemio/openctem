package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/pkg/logger"
)

const pathToken = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8"

func TestRedactPath(t *testing.T) {
	for in, want := range map[string]string{
		"/api/v1/invitations/" + pathToken:                          "/api/v1/invitations/{redacted}",
		"/api/v1/invitations/" + pathToken + "/preview":             "/api/v1/invitations/{redacted}/preview",
		"/api/v1/invitations/" + pathToken + "/accept-with-refresh": "/api/v1/invitations/{redacted}/accept-with-refresh",
		// The body routes name no secret and stay readable.
		"/api/v1/invitations/lookup":              "/api/v1/invitations/lookup",
		"/api/v1/invitations/accept":              "/api/v1/invitations/accept",
		"/api/v1/invitations/accept-with-refresh": "/api/v1/invitations/accept-with-refresh",
		"/api/v1/invitations/decline":             "/api/v1/invitations/decline",
		"/api/v1/invitations/":                    "/api/v1/invitations/",
		"/api/v1/invitations":                     "/api/v1/invitations",
		// Other paths are untouched, including the tenant-scoped invitation list.
		"/api/v1/tenants/acme/invitations/0b6c1a52-6c1f-4b8e-9d55-5d0f6e8c2a11": "/api/v1/tenants/acme/invitations/0b6c1a52-6c1f-4b8e-9d55-5d0f6e8c2a11",
		"/api/v1/findings": "/api/v1/findings",
	} {
		if got := RedactPath(in); got != want {
			t.Errorf("RedactPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A request to a deprecated token-in-path route leaves no trace of the token
// in the access log or in the HTTP metric labels.
func TestTokenPathIsNotLoggedOrLabelled(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New(logger.Config{Level: "info", Format: "json", Output: &buf})
	path := "/api/v1/invitations/" + pathToken + "/preview"

	h := Metrics()(LoggerWithConfig(log, LoggerConfig{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound) // logged at WARN, never skipped
	})))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))

	if strings.Contains(buf.String(), pathToken) {
		t.Fatalf("access log carries the token: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "/api/v1/invitations/{redacted}/preview") {
		t.Fatalf("access log lost the route shape: %s", buf.String())
	}

	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, "/api/v1/invitations/{redacted}/preview", "404")); got < 1 {
		t.Fatalf("request not counted under the redacted path label (got %v)", got)
	}
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if strings.Contains(l.GetValue(), pathToken) {
					t.Fatalf("metric %s label %s carries the token", f.GetName(), l.GetName())
				}
			}
		}
	}
}

func TestNormalizePathRedacts(t *testing.T) {
	if got := normalizePath("/api/v1/invitations/" + pathToken + "/accept"); strings.Contains(got, pathToken) {
		t.Fatalf("normalizePath kept the token: %s", got)
	}
}

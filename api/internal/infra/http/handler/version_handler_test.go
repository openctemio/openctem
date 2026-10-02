package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/version"
)

func TestVersionHandler(t *testing.T) {
	oldV, oldC, oldT := version.Version, version.Commit, version.BuildTime
	t.Cleanup(func() { version.Version, version.Commit, version.BuildTime = oldV, oldC, oldT })
	version.Version = "v0.9.0"
	version.Commit = "4d2f4b02aa11bb22cc33dd44ee55ff6677889900"
	version.BuildTime = "2026-10-02T10:00:00Z"

	rec := httptest.NewRecorder()
	Version(rec, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"version":    "v0.9.0",
		"commit":     "4d2f4b02",
		"build_time": "2026-10-02T10:00:00Z",
		"channel":    "release",
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %q, want %q", k, body[k], v)
		}
	}
}

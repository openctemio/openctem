package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/server/pkg/version"
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
	var body version.Info
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := version.Info{Version: "v0.9.0", Commit: "4d2f4b02", BuildTime: "2026-10-02T10:00:00Z", Channel: "release", ExtensionAPI: version.ExtensionAPI}
	if body.Version != want.Version || body.Commit != want.Commit || body.BuildTime != want.BuildTime ||
		body.Channel != want.Channel || body.ExtensionAPI != want.ExtensionAPI {
		t.Errorf("body = %+v, want %+v", body, want)
	}
	// The Community build lists no extension: an empty list, never null.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["extensions"]) != "[]" {
		t.Errorf("extensions = %s, want []", raw["extensions"])
	}
}

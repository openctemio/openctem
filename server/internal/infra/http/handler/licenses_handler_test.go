package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/openctem/api/pkg/notices"
)

func getLicenses(t *testing.T, h *LicensesHandler) notices.Document {
	t.Helper()
	rec := httptest.NewRecorder()
	// A query string never chooses the file: the path is fixed at construction.
	h.List(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/licenses?path=/etc/passwd", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q", ct)
	}
	var doc notices.Document
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not a notices document: %v", err)
	}
	return doc
}

func TestLicensesHandler_ServesTheNoticesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), notices.DefaultPath)
	body := `{"generated":true,"component":"api","packages":[{"name":"example.com/mit","version":"v1.0.0","license":"MIT","text":"Permission is hereby granted"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := getLicenses(t, NewLicensesHandler(path, nil))
	if !doc.Generated || doc.Component != "api" || len(doc.Packages) != 1 || doc.Packages[0].Name != "example.com/mit" {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestLicensesHandler_MissingFileIsAnEmptyList(t *testing.T) {
	doc := getLicenses(t, NewLicensesHandler(filepath.Join(t.TempDir(), "absent.json"), nil))
	if doc.Generated || doc.Packages == nil || len(doc.Packages) != 0 {
		t.Fatalf("doc = %+v, want generated=false and an empty list", doc)
	}
}

func TestLicensesHandler_MalformedFileIsAnEmptyList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := getLicenses(t, NewLicensesHandler(path, nil))
	if doc.Generated || len(doc.Packages) != 0 {
		t.Fatalf("doc = %+v, want generated=false and an empty list", doc)
	}
}

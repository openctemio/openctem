package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The content pack API end to end: HTTP, service, Postgres (migration
// 001380) and file storage. Requires DATABASE_URL (a migrated _test
// database).

func contentPackTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(data))
	}
	_ = tw.Close()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()
	return out.Bytes()
}

func contentPackUpload(t *testing.T, fields map[string]string, archive []byte) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	if archive != nil {
		fw, _ := mw.CreateFormFile("archive", "pack.tar.gz")
		_, _ = fw.Write(archive)
	}
	_ = mw.Close()
	return &body, mw.FormDataContentType()
}

func TestContentPackAPI(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	seed := func() string {
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'cp', $2)`, id, "cp-"+id); err != nil {
			t.Skip(err)
		}
		return id
	}
	tenantA, tenantB := seed(), seed()

	signer, _ := contentpack.NewSigner(bytes.Repeat([]byte{3}, 32))
	svc := contentpackapp.NewService(postgres.NewContentPackRepository(&postgres.DB{DB: db}),
		storage.NewLocalStorage(t.TempDir()), signer, nil, logger.NewNop())
	h := NewContentPackHandler(svc, logger.NewNop())
	r := chi.NewRouter()
	r.Get("/content-packs/signing-key", h.SigningKey)
	r.Get("/content-packs/{id}", h.Get)
	r.Get("/content-packs/{id}/download", h.Download)
	r.Post("/content-packs", h.Upload)
	r.Post("/content-packs/{id}/revoke", h.Revoke)
	do := func(tenant, method, path string, body *bytes.Buffer, ctype string) *httptest.ResponseRecorder {
		if body == nil {
			body = &bytes.Buffer{}
		}
		req := httptest.NewRequest(method, path, body)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	body, ct := contentPackUpload(t, map[string]string{"name": "org-words", "version": "2026.10.08", "kind": "wordlist"},
		contentPackTar(t, map[string]string{"dirs/common.txt": "admin\nbackup\n"}))
	rec := do(tenantA, http.MethodPost, "/content-packs", body, ct)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	var p ContentPackResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if p.Tier != "T0" || p.FileCount != 1 || p.Lint.Items != 2 || !strings.HasPrefix(p.Digest, "sha256:") {
		t.Fatalf("pack %+v", p)
	}

	rec = do(tenantA, http.MethodGet, "/content-packs/"+p.ID+"/download", nil, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Digest") != p.Digest || rec.Header().Get("Content-Type") != "application/x-tar" {
		t.Fatalf("archive: %d %v", rec.Code, rec.Header())
	}
	if _, err := contentpack.ReadCanonical(rec.Body.Bytes(), p.Digest); err != nil {
		t.Fatalf("downloaded archive: %v", err)
	}

	// SECURITY: another tenant gets 404 for the pack and its archive.
	for _, path := range []string{"/content-packs/" + p.ID, "/content-packs/" + p.ID + "/download"} {
		if rec := do(tenantB, http.MethodGet, path, nil, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant %s: %d", path, rec.Code)
		}
	}

	// Lint refusal carries the report; a symlink is a 400.
	body, ct = contentPackUpload(t, map[string]string{"name": "bad", "version": "1", "kind": "nuclei-templates"},
		contentPackTar(t, map[string]string{"x.yaml": "id: x\ninfo: {name: x, severity: high}\ncode:\n  - engine: [sh]\n    source: id\n"}))
	rec = do(tenantA, http.MethodPost, "/content-packs", body, ct)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "CONTENT_LINT_FAILED") || !strings.Contains(rec.Body.String(), "DANGEROUS_PATTERN") {
		t.Fatalf("lint refusal: %d %s", rec.Code, rec.Body)
	}
	body, ct = contentPackUpload(t, map[string]string{"name": "dup", "version": "2026.10.08", "kind": "wordlist"}, nil)
	if rec := do(tenantA, http.MethodPost, "/content-packs", body, ct); rec.Code != http.StatusBadRequest {
		t.Fatalf("no archive: %d", rec.Code)
	}
	body, ct = contentPackUpload(t, map[string]string{"name": "org-words", "version": "2026.10.08", "kind": "wordlist"},
		contentPackTar(t, map[string]string{"other.txt": "x\n"}))
	if rec := do(tenantA, http.MethodPost, "/content-packs", body, ct); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate version: %d %s", rec.Code, rec.Body)
	}

	rec = do(tenantA, http.MethodPost, "/content-packs/"+p.ID+"/revoke", bytes.NewBufferString(`{"reason":"superseded"}`), "application/json")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"revoked"`) {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if rec := do(tenantA, http.MethodPost, "/content-packs/"+p.ID+"/revoke", bytes.NewBufferString(`{"reason":"again"}`), "application/json"); rec.Code != http.StatusConflict {
		t.Fatalf("revoke twice: %d", rec.Code)
	}
	if rec := do(tenantA, http.MethodGet, "/content-packs/signing-key", nil, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ed25519") {
		t.Fatalf("signing key: %d %s", rec.Code, rec.Body)
	}
}

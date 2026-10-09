package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The platform content pack API end to end (handler, service, Postgres
// migration 001546, file storage): upload, channels, revocation with
// rollback, download. Route gating (admin roles, tenant permission) is
// covered by the route tests. Requires DATABASE_URL.
func TestPlatformContentPackAPI(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	signer, _ := contentpack.NewSigner(bytes.Repeat([]byte{4}, 32))
	svc := contentpackapp.NewPlatformService(postgres.NewPlatformContentPackRepository(&postgres.DB{DB: db}),
		storage.NewLocalStorage(t.TempDir()), signer, logger.NewNop())
	h := NewPlatformContentPackHandler(svc, fakeStepUp{}, nil, logger.NewNop())
	r := chi.NewRouter()
	r.Post("/admin/content-packs", h.Upload)
	r.Get("/admin/content-packs/{id}/download", h.Download)
	r.Post("/admin/content-packs/{id}/revoke", h.Revoke)
	r.Put("/admin/content-packs/channels/{channel}", h.SetChannel)
	r.Get("/platform-content-packs/channels", h.Channels)
	r.Get("/platform-content-packs/{id}", h.Get)
	do := func(method, path string, body *bytes.Buffer, ctype string) *httptest.ResponseRecorder {
		if body == nil {
			body = &bytes.Buffer{}
		}
		su, _ := admin.NewAdminUser("super@op.example", "Super", admin.AdminRoleSuperAdmin, nil)
		req := httptest.NewRequest(method, path, body)
		req = req.WithContext(context.WithValue(req.Context(), middleware.AdminUserKey, su))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	name := "words-" + strings.ReplaceAll(shared.NewID().String()[24:], "-", "")
	upload := func(version, words string) PlatformContentPackResponse {
		body, ct := contentPackUpload(t, map[string]string{"name": name, "version": version, "kind": "wordlist", "reason": "upstream release", "totp_code": "123456"},
			contentPackTar(t, map[string]string{"common.txt": name + "\n" + words}))
		rec := do(http.MethodPost, "/admin/content-packs", body, ct)
		if rec.Code != http.StatusCreated {
			t.Fatalf("upload %s: %d %s", version, rec.Code, rec.Body)
		}
		var p PlatformContentPackResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		return p
	}
	v1 := upload("1", "admin\n")
	v2 := upload("2", "admin\nbackup\n")

	for _, c := range []struct{ id, ch string }{{v1.ID, "stable"}, {v2.ID, "canary"}} {
		if rec := do(http.MethodPut, "/admin/content-packs/channels/"+c.ch, bytes.NewBufferString(`{"pack_id":"`+c.id+`","reason":"r","totp_code":"123456"}`), "application/json"); rec.Code != http.StatusOK {
			t.Fatalf("set %s: %d %s", c.ch, rec.Code, rec.Body)
		}
	}
	if rec := do(http.MethodPut, "/admin/content-packs/channels/beta", bytes.NewBufferString(`{"pack_id":"`+v1.ID+`","reason":"r","totp_code":"123456"}`), "application/json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown channel: %d", rec.Code)
	}
	// Promote v2 to stable, then revoke it: stable rolls back to v1 and the
	// canary channel (also v2) has nothing older but v1 either.
	_ = do(http.MethodPut, "/admin/content-packs/channels/stable", bytes.NewBufferString(`{"pack_id":"`+v2.ID+`","reason":"r","totp_code":"123456"}`), "application/json")
	rec := do(http.MethodPost, "/admin/content-packs/"+v2.ID+"/revoke", bytes.NewBufferString(`{"reason":"bad list","totp_code":"123456"}`), "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	var rv RevokePlatformContentPackResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &rv)
	if rv.Pack.Status != "revoked" || len(rv.Channels) != 2 || rv.Channels[0].PackID != v1.ID || rv.Channels[1].PackID != v1.ID {
		t.Fatalf("after revoke: %+v", rv)
	}
	if rec := do(http.MethodGet, "/platform-content-packs/channels", nil, ""); !strings.Contains(rec.Body.String(), v1.Digest) {
		t.Fatalf("channels: %s", rec.Body)
	}
	if rec := do(http.MethodGet, "/platform-content-packs/"+v1.ID, nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("tenant view: %d", rec.Code)
	}
	rec = do(http.MethodGet, "/admin/content-packs/"+v1.ID+"/download", nil, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Digest") != v1.Digest {
		t.Fatalf("download: %d", rec.Code)
	}
	if _, err := contentpack.ReadPlatformCanonical(rec.Body.Bytes(), v1.Digest); err != nil {
		t.Fatal(err)
	}
}

// Each platform pack write needs a reason and a confirmed authenticator
// code before anything changes; without a verifier nothing runs.
func TestPlatformContentPackWritesNeedStepUp(t *testing.T) {
	svc := contentpackapp.NewPlatformService(nil, nil, nil, logger.NewNop())
	su, _ := admin.NewAdminUser("super@op.example", "Super", admin.AdminRoleSuperAdmin, nil)
	run := func(fn http.HandlerFunc, body *bytes.Buffer, ctype string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/x", body)
		req.Header.Set("Content-Type", ctype)
		req = req.WithContext(context.WithValue(req.Context(), middleware.AdminUserKey, su))
		rec := httptest.NewRecorder()
		fn(rec, req)
		return rec
	}
	form := func(fields map[string]string) (*bytes.Buffer, string) {
		return contentPackUpload(t, fields, contentPackTar(t, map[string]string{"w.txt": "a\n"}))
	}
	h := NewPlatformContentPackHandler(svc, fakeStepUp{}, nil, logger.NewNop())
	b, ct := form(map[string]string{"name": "w", "version": "1", "kind": "wordlist", "totp_code": "123456"})
	if rec := run(h.Upload, b, ct); rec.Code != http.StatusBadRequest {
		t.Fatalf("upload without a reason: %d", rec.Code)
	}
	b, ct = form(map[string]string{"name": "w", "version": "1", "kind": "wordlist", "reason": "r"})
	if rec := run(h.Upload, b, ct); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("upload without a code: %d %s", rec.Code, rec.Body)
	}
	bad := NewPlatformContentPackHandler(svc, fakeStepUp{err: admin.ErrInvalidMFACode}, nil, logger.NewNop())
	b, ct = form(map[string]string{"name": "w", "version": "1", "kind": "wordlist", "reason": "r", "totp_code": "000000"})
	if rec := run(bad.Upload, b, ct); rec.Code != http.StatusUnauthorized {
		t.Fatalf("upload with a wrong code: %d", rec.Code)
	}
	imp := `{"name":"w","version":"1","kind":"wordlist","url":"https://example.org/x","digest":"sha256:` + strings.Repeat("a", 64) + `","reason":"r","totp_code":"000000"}`
	if rec := run(bad.Import, bytes.NewBufferString(imp), "application/json"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("import with a wrong code: %d", rec.Code)
	}
	none := NewPlatformContentPackHandler(svc, nil, nil, logger.NewNop())
	if rec := run(none.Revoke, bytes.NewBufferString(`{"reason":"r","totp_code":"123456"}`), "application/json"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no verifier: %d (an unconfirmed write must never run)", rec.Code)
	}
}

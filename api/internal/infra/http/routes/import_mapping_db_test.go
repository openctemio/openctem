package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Import mappings against the real database (docs/rfcs/RFC-126-import-mappings.md):
// CRUD and versions, the identity confirmation, tenant isolation of every
// route and of format=mapping:<ref> on import, and an import through a
// mapping landing partial-coverage findings recorded under its name.

const dbMappingDoc = `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "identity": ["title", "asset_value"],
  "records": [{"kind": "finding", "set": {"title": "/title", "severity": {"path": "/severity", "lower": true},
    "asset_value": "/host", "asset_type": {"const": "domain"}, "description": "/note"}}]}`

type mappingHarness struct {
	*importHarness
	mh     *handler.ImportMappingHandler
	other  string // a second organization
	tenant string
}

func newMappingHarness(t *testing.T) *mappingHarness {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	repo := postgres.NewImportMappingRepository(&postgres.DB{DB: ih.db})
	svc := appimportmapping.NewService(repo)
	ih.h.SetMappingResolver(svc)
	ih.svc.SetMappingResolver(svc)
	other := shared.NewID()
	if _, err := ih.db.ExecContext(context.Background(), `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`,
		other.String(), "mapping-other-"+other.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, tid := range []string{ih.tenantID, other.String()} {
			_, _ = ih.db.ExecContext(context.Background(), `DELETE FROM import_mappings WHERE tenant_id = $1`, tid)
		}
		_, _ = ih.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	audit := auditapp.NewAuditService(postgres.NewAuditRepository(&postgres.DB{DB: ih.db}), logger.NewNop())
	return &mappingHarness{importHarness: ih, mh: handler.NewImportMappingHandler(svc, audit, logger.NewNop()),
		other: other.String(), tenant: ih.tenantID}
}

func (m *mappingHarness) call(t *testing.T, tenant string, fn http.HandlerFunc, method, target string, body []byte, params map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rc := chi.NewRouteContext()
	for k, v := range params {
		rc.URLParams.Add(k, v)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rc)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, tenant)
	rec := httptest.NewRecorder()
	fn(rec, req.WithContext(ctx))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func jsonBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestImportMappings_DB(t *testing.T) {
	m := newMappingHarness(t)

	// Create in the first organization.
	rec, out := m.call(t, m.tenant, m.mh.Create, http.MethodPost, "/api/v1/import-mappings",
		jsonBody(t, map[string]any{"name": "legacy-vm", "description": "export of the old tool", "mapping": json.RawMessage(dbMappingDoc)}), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	id := out["mapping"].(map[string]any)["id"].(string)

	// A reserved member is refused with the problem named.
	reserved := strings.Replace(dbMappingDoc, `"description": "/note"`, `"fingerprint": "/id"`, 1)
	if rec, _ := m.call(t, m.tenant, m.mh.Create, http.MethodPost, "/", jsonBody(t, map[string]any{"name": "bad", "mapping": json.RawMessage(reserved)}), nil); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "reserved") {
		t.Fatalf("reserved: %d %s", rec.Code, rec.Body)
	}

	// Every by-id route answers 404 to the other organization.
	p := map[string]string{"id": id, "version_id": "1"}
	for name, fn := range map[string]http.HandlerFunc{"get": m.mh.Get, "version": m.mh.GetVersion, "patch": m.mh.Update, "delete": m.mh.Delete, "add": m.mh.AddVersion} {
		body := []byte(`{}`)
		if name == "add" {
			body = jsonBody(t, map[string]any{"mapping": json.RawMessage(dbMappingDoc)})
		}
		if rec, _ := m.call(t, m.other, fn, http.MethodPost, "/", body, p); rec.Code != http.StatusNotFound {
			t.Fatalf("%s across organizations: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec, out := m.call(t, m.other, m.mh.List, http.MethodGet, "/", nil, nil); rec.Code != http.StatusOK || len(out["items"].([]any)) != 0 {
		t.Fatalf("list across organizations: %d %s", rec.Code, rec.Body)
	}

	// An identity change is never saved silently.
	rekey := strings.Replace(dbMappingDoc, `"asset_value": "/host"`, `"asset_value": "/fqdn"`, 1)
	rec, out = m.call(t, m.tenant, m.mh.AddVersion, http.MethodPost, "/", jsonBody(t, map[string]any{"mapping": json.RawMessage(rekey)}), p)
	if rec.Code != http.StatusConflict || out["code"] != string(handler.CodeIdentityChangeUnconfirmed) {
		t.Fatalf("unconfirmed: %d %s", rec.Code, rec.Body)
	}
	rec, out = m.call(t, m.tenant, m.mh.AddVersion, http.MethodPost, "/", jsonBody(t, map[string]any{"mapping": json.RawMessage(rekey), "confirm_identity_change": true, "note": "host column renamed"}), p)
	if rec.Code != http.StatusCreated || out["version"].(map[string]any)["identity_changed"] != true {
		t.Fatalf("confirmed: %d %s", rec.Code, rec.Body)
	}
	// Back to version 1's shape for the import below (another confirmed change).
	if rec, _ := m.call(t, m.tenant, m.mh.AddVersion, http.MethodPost, "/", jsonBody(t, map[string]any{"mapping": json.RawMessage(dbMappingDoc), "confirm_identity_change": true}), p); rec.Code != http.StatusCreated {
		t.Fatalf("v3: %d %s", rec.Code, rec.Body)
	}
	rec, out = m.call(t, m.tenant, m.mh.Get, http.MethodGet, "/", nil, p)
	if rec.Code != http.StatusOK || len(out["versions"].([]any)) != 3 {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body)
	}

	csv := []byte("title,severity,host,note\nOpenSSL out of date,High,web-01.example.com,upgrade\nWeak TLS,medium,web-01.example.com,\n")

	// The other organization cannot import through this mapping, by name or id.
	for _, ref := range []string{"legacy-vm", id, "legacy-vm@1"} {
		rec, _ := m.upload(t, m.other, "?format=mapping:"+ref, "export.csv", csv, true)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), string(handler.CodeUnknownMapping)) {
			t.Fatalf("import across organizations (%s): %d %s", ref, rec.Code, rec.Body)
		}
	}
	// A mapped import is always partial coverage.
	if rec, _ := m.upload(t, m.tenant, "?format=mapping:legacy-vm&coverage=full&asset_id="+shared.NewID().String(), "export.csv", csv, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("coverage=full: %d %s", rec.Code, rec.Body)
	}

	// The import lands the findings in the owner organization.
	rec, resp := m.upload(t, m.tenant, "?format=mapping:legacy-vm", "export.csv", csv, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	if len(resp.Files) != 1 || resp.Files[0].Format != "mapping:legacy-vm@3" {
		t.Fatalf("files %+v", resp.Files)
	}
	if n := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, m.tenant); n != 2 {
		t.Fatalf("findings in the owner organization: %d", n)
	}
	if n := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, m.other); n != 0 {
		t.Fatalf("findings in the other organization: %d", n)
	}
	if n := m.count(t, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1 AND format = 'mapping:legacy-vm@3'`, m.tenant); n != 1 {
		t.Fatalf("receipt with the mapping format: %d", n)
	}

	// Preview of the saved mapping, and a preview from the other
	// organization by id answers 404.
	prev := previewRequest(t, map[string]string{"mapping_id": id}, csv)
	rec, out = m.callRaw(t, m.tenant, m.mh.Preview, prev)
	if rec.Code != http.StatusOK || len(out["items"].([]any)) != 2 {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := m.callRaw(t, m.other, m.mh.Preview, previewRequest(t, map[string]string{"mapping_id": id}, csv)); rec.Code != http.StatusNotFound {
		t.Fatalf("preview across organizations: %d %s", rec.Code, rec.Body)
	}
	// A preview stores nothing.
	before := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, m.tenant)
	if rec, _ := m.callRaw(t, m.tenant, m.mh.Preview, previewRequest(t, map[string]string{"mapping": dbMappingDoc}, []byte("title,severity,host\nNew,high,new.example.com\n"))); rec.Code != http.StatusOK {
		t.Fatalf("draft preview: %d %s", rec.Code, rec.Body)
	}
	if after := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, m.tenant); after != before {
		t.Fatalf("preview wrote findings: %d -> %d", before, after)
	}

	// Rename, then delete; the findings it imported stay.
	if rec, _ := m.call(t, m.tenant, m.mh.Update, http.MethodPatch, "/", jsonBody(t, map[string]any{"name": "legacy-vm-2"}), p); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := m.call(t, m.tenant, m.mh.Delete, http.MethodDelete, "/", nil, p); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	// Every write is audited in the owner organization, the confirmed
	// identity change marked; nothing is audited in the other one (its
	// refused attempts changed nothing).
	for action, want := range map[string]int{"import_mapping.created": 1, "import_mapping.version_created": 2,
		"import_mapping.updated": 1, "import_mapping.deleted": 1} {
		if n := m.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2 AND resource_type = 'import_mapping' AND resource_id = $3`, m.tenant, action, id); n != want {
			t.Errorf("audit %s: %d rows, want %d", action, n, want)
		}
	}
	if n := m.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'import_mapping.version_created' AND (metadata->>'identity_changed')::boolean`, m.tenant); n != 2 {
		t.Errorf("identity changes audited: %d, want 2", n)
	}
	if n := m.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND resource_type = 'import_mapping'`, m.other); n != 0 {
		t.Errorf("audit rows in the other organization: %d", n)
	}
	if n := m.count(t, `SELECT count(*) FROM import_mapping_versions WHERE tenant_id = $1`, m.tenant); n != 0 {
		t.Fatalf("versions left: %d", n)
	}
	if n := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, m.tenant); n != 2 {
		t.Fatalf("findings after delete: %d", n)
	}
}

func previewRequest(t *testing.T, fields map[string]string, sample []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	w, _ := mw.CreateFormFile("file", "sample.csv")
	_, _ = w.Write(sample)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/import-mappings/preview", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func (m *mappingHarness) callRaw(t *testing.T, tenant string, fn http.HandlerFunc, req *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
	rec := httptest.NewRecorder()
	fn(rec, req.WithContext(ctx))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

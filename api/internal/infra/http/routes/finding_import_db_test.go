package routes

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ctisImporterFixtures returns the input fixtures of the pinned ctis
// importers (every format the pin ships), from the module cache.
func ctisImporterFixtures(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/openctemio/ctis").Output()
	if err != nil {
		t.Skipf("ctis module not resolvable: %v", err)
	}
	all, _ := filepath.Glob(filepath.Join(strings.TrimSpace(string(out)), "testdata", "importers", "*", "*"))
	var inputs []string
	for _, p := range all {
		b := filepath.Base(p)
		if strings.HasSuffix(b, ".golden.json") || strings.HasSuffix(b, ".result.json") || strings.HasSuffix(b, ".kb.xml") {
			continue
		}
		inputs = append(inputs, p)
	}
	if len(inputs) == 0 {
		t.Skip("no ctis importer fixtures")
	}
	return inputs
}

type importHarness struct {
	*v2Harness
	h *handler.FindingImportHandler
}

func newImportHarness(t *testing.T, mode ingest.VEXMode) *importHarness {
	v2 := newV2Harness(t, v2HarnessOpts{})
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM findings WHERE tenant_id = $1`, `DELETE FROM asset_identifiers WHERE tenant_id = $1`,
			`DELETE FROM assets WHERE tenant_id = $1`, `DELETE FROM audit_logs WHERE tenant_id = $1`} {
			_, _ = v2.db.ExecContext(context.Background(), q, v2.tenantID)
		}
	})
	pdb := &postgres.DB{DB: v2.db}
	svc := findingimport.NewService(v2.ingest, postgres.NewFindingRepository(pdb), mode, logger.NewNop())
	h := handler.NewFindingImportHandler(svc, nil, nil, logger.NewNop())
	h.SetActorResolver(func(context.Context, shared.ID) (ingest.ActorScope, error) { return nil, nil })
	return &importHarness{v2Harness: v2, h: h}
}

func (ih *importHarness) upload(t *testing.T, tenant, query, name string, data []byte, admin bool) (*httptest.ResponseRecorder, handler.FindingImportResponse) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("file", name)
	_, _ = w.Write(data)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/import"+query, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
	if admin {
		ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	}
	rec := httptest.NewRecorder()
	ih.h.Import(rec, req.WithContext(ctx))
	var resp handler.FindingImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp
}

func (ih *importHarness) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := ih.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Every fixture of the pinned ctis importers goes through the real handler,
// ingest and database: a preview writes nothing, the import lands the
// findings in the uploader's tenant.
func TestFindingImport_RealFixtures_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	for _, p := range ctisImporterFixtures(t) {
		name := filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			before := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, ih.tenantID)
			rec, resp := ih.upload(t, ih.tenantID, "?dry_run=true", filepath.Base(p), data, true)
			if rec.Code != http.StatusOK || len(resp.Files) != 1 || resp.Files[0].Error != nil {
				t.Fatalf("preview %d: %s", rec.Code, rec.Body.String())
			}
			if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, ih.tenantID); n != before {
				t.Fatalf("a preview wrote %d findings", n-before)
			}
			rec, resp = ih.upload(t, ih.tenantID, "", filepath.Base(p), data, true)
			if rec.Code != http.StatusOK || resp.Files[0].Error != nil {
				t.Fatalf("import %d: %s", rec.Code, rec.Body.String())
			}
			f := resp.Files[0]
			if f.Stats.Findings > 0 {
				if f.Ingest == nil || f.Ingest.FindingsCreated+f.Ingest.FindingsUpdated == 0 {
					t.Fatalf("findings not ingested: %s", rec.Body.String())
				}
				if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, ih.tenantID); n <= before && f.Ingest.FindingsUpdated == 0 {
					t.Fatalf("no finding stored")
				}
			}
			if f.Stats.Statements > 0 && f.VEX == nil {
				t.Fatalf("VEX statements not applied: %s", rec.Body.String())
			}
		})
	}
	// Nothing landed in another tenant.
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id <> $1 AND tool_name = 'nessus' AND created_at > now() - interval '1 minute' AND fingerprint IN (SELECT fingerprint FROM findings WHERE tenant_id = $1)`, ih.tenantID); n != 0 {
		t.Fatalf("%d findings landed in another tenant", n)
	}
}

// An OpenVEX statement about a component inside one image closes (enforce,
// admin) only that image's finding: not the same package's finding on
// another asset, not another tenant's, and nothing in a preview.
func TestFindingImport_VEXDocument_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveEnforce)
	ctx := context.Background()
	compID := shared.NewID()
	purl := "pkg:golang/example.com/libexample@v1.4.2-" + compID.String()[:8]
	if _, err := ih.db.ExecContext(ctx, `INSERT INTO components (id, purl, name, version, ecosystem) VALUES ($1, $2, 'libexample', 'v1.4.2', 'go')`, compID, purl); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = ih.db.ExecContext(context.Background(), `DELETE FROM components WHERE id = $1`, compID) })
	asset := func(tenant, name string) shared.ID {
		id := shared.NewID()
		if _, err := ih.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'container')`, id, tenant, name); err != nil {
			t.Fatal(err)
		}
		return id
	}
	finding := func(tenant string, assetID shared.ID) shared.ID {
		id := shared.NewID()
		if _, err := ih.db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, component_id, source, tool_name, message, severity, fingerprint, status, cve_id)
			VALUES ($1, $2, $3, $4, 'sca', 'trivy', 'm', 'high', $5, 'open', 'CVE-2025-1111')`, id, tenant, assetID, compID, "fp-"+id.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	web := finding(ih.tenantID, asset(ih.tenantID, "registry.example.com/web"))
	other := finding(ih.tenantID, asset(ih.tenantID, "registry.example.com/other"))

	otherTenant := shared.NewID().String()
	if _, err := ih.db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, otherTenant, "imp-o-"+otherTenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = ih.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, otherTenant)
	})
	foreign := finding(otherTenant, asset(otherTenant, "registry.example.com/web"))

	var doc []byte
	for _, p := range ctisImporterFixtures(t) {
		if strings.HasSuffix(p, filepath.Join("openvex", "image-vex.json")) {
			doc, _ = os.ReadFile(p)
		}
	}
	if doc == nil {
		t.Skip("the pinned ctis has no OpenVEX fixture")
	}
	// The fixture's component has no version suffix; match by base.
	status := func(id shared.ID) (string, string) {
		var s, v string
		_ = ih.db.QueryRow(`SELECT status, COALESCE(vex_status, '') FROM findings WHERE id = $1`, id).Scan(&s, &v)
		return s, v
	}

	rec, resp := ih.upload(t, ih.tenantID, "?dry_run=true", "image.vex.json", doc, true)
	if rec.Code != http.StatusOK || resp.Files[0].VEX == nil || resp.Files[0].VEX.Matched != 1 || resp.Files[0].VEX.WouldClose != 1 {
		t.Fatalf("preview: %s", rec.Body.String())
	}
	if s, v := status(web); s != "open" || v != "" {
		t.Fatalf("a preview changed the finding: %s %s", s, v)
	}

	// Without findings:approve (not admin, no permission): stored, not closed.
	rec, resp = ih.upload(t, ih.tenantID, "", "image.vex.json", doc, false)
	if rec.Code != http.StatusOK || resp.Files[0].VEX.Closed != 0 || resp.Files[0].VEX.Stored != 1 {
		t.Fatalf("no-approve import: %s", rec.Body.String())
	}
	if s, v := status(web); s != "open" || v != "not_affected" {
		t.Fatalf("no-approve: %s %s", s, v)
	}

	rec, resp = ih.upload(t, ih.tenantID, "", "image.vex.json", doc, true)
	if rec.Code != http.StatusOK || resp.Files[0].VEX.Closed != 1 {
		t.Fatalf("import: %s", rec.Body.String())
	}
	if s, _ := status(web); s != "false_positive" {
		t.Fatalf("the image's finding = %s, want false_positive", s)
	}
	if s, v := status(other); s != "open" || v != "" {
		t.Fatalf("the same package on another image changed: %s %s", s, v)
	}
	if s, v := status(foreign); s != "open" || v != "" {
		t.Fatalf("another tenant's finding changed: %s %s", s, v)
	}
}

// A ZIP of a Qualys detection file and its KnowledgeBase: the archive is
// read under its limits, the KnowledgeBase is paired with the detections
// and not imported as a file of its own.
func TestFindingImport_QualysPairInArchive_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	var det, kb []byte
	for _, p := range ctisImporterFixtures(t) {
		if strings.HasSuffix(p, filepath.Join("qualys", "detections.xml")) {
			det, _ = os.ReadFile(p)
			kb, _ = os.ReadFile(strings.TrimSuffix(p, ".xml") + ".kb.xml")
		}
	}
	if det == nil || kb == nil {
		t.Skip("the pinned ctis has no Qualys fixture pair")
	}
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, data := range map[string][]byte{"export/detections.xml": det, "export/kb.xml": kb} {
		w, _ := zw.Create(name)
		_, _ = w.Write(data)
	}
	_ = zw.Close()
	rec, resp := ih.upload(t, ih.tenantID, "", "qualys.zip", zbuf.Bytes(), true)
	if rec.Code != http.StatusOK || len(resp.Files) != 1 || resp.Files[0].Error != nil || resp.Files[0].Format != "qualys" {
		t.Fatalf("%d: %s", rec.Code, rec.Body.String())
	}
	if resp.Files[0].Ingest == nil || resp.Files[0].Ingest.FindingsCreated == 0 {
		t.Fatalf("nothing ingested: %s", rec.Body.String())
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND tool_name = $2`, ih.tenantID, "qualys"); n == 0 {
		t.Fatal("no Qualys finding stored")
	}
}

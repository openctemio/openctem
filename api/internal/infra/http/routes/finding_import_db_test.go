package routes

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/testdb"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/ingestqueue"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
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
		if strings.HasSuffix(b, ".golden.json") || strings.HasSuffix(b, ".result.json") || strings.HasSuffix(b, ".kb.xml") || strings.HasSuffix(b, ".options.json") || strings.HasSuffix(b, ".legacy.json") {
			continue
		}
		// A directory is a recon bundle (several files), uploaded as an
		// archive and covered by the findingimport bundle tests.
		if st, err := os.Stat(p); err != nil || st.IsDir() {
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
	h   *handler.FindingImportHandler
	svc *findingimport.Service
	// Committed uploads are applied by the ingest worker; the harness
	// drains the queue itself and reads the result as a client does.
	queue    *ingestqueue.Queue
	jp       *ingest.JobProcessor
	worker   *controller.IngestWorkerController
	receipts *handler.IngestReceiptHandler
	userID   string
}

// wire gives svc the harness's queue (resolve decides the uploader's scope
// in the worker; nil is unrestricted) and makes it the worker's importer.
func (ih *importHarness) wire(svc *findingimport.Service, resolve findingimport.ScopeResolver) {
	if resolve == nil {
		resolve = func(context.Context, shared.ID, findingimport.Caller) (ingest.ActorScope, ingest.ActorScope, error) {
			return nil, nil, nil
		}
	}
	svc.SetQueue(ih.queue, resolve, nil)
	ih.jp.SetKind(ingestjob.KindFindingImport, ingest.KindFuncs{ProcessFn: svc.ProcessImportJob, DeadLetterFn: svc.DeadLetter})
	ih.receipts.SetImportResults(svc)
}

// finish applies a stored upload and reads its result (202 stays the code).
func (ih *importHarness) finish(t *testing.T, rec *httptest.ResponseRecorder, resp handler.FindingImportResponse) handler.FindingImportResponse {
	t.Helper()
	if rec.Code != http.StatusAccepted {
		return resp
	}
	if _, err := ih.worker.Reconcile(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/imports/"+resp.ReceiptID+"/result", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", resp.ReceiptID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, ih.tenantID)
	w := httptest.NewRecorder()
	ih.receipts.Result(w, req.WithContext(ctx))
	var out handler.FindingImportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
		t.Fatalf("import result: %d %s", w.Code, w.Body.String())
	}
	return out
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
	receipts := postgres.NewIngestReceiptRepository(pdb)
	v2.ingest.SetReceiptRecorder(receipts)
	t.Cleanup(func() {
		_, _ = v2.db.ExecContext(context.Background(), `DELETE FROM ingest_receipts WHERE tenant_id = $1`, v2.tenantID)
		_, _ = v2.db.ExecContext(context.Background(), `DELETE FROM dash_ingest_day WHERE tenant_id = $1`, v2.tenantID)
	})
	svc := findingimport.NewService(v2.ingest, postgres.NewFindingRepository(pdb), receipts, mode, logger.NewNop())
	h := handler.NewFindingImportHandler(svc, nil, nil, logger.NewNop())
	h.SetActorResolver(func(context.Context, shared.ID) (ingest.ActorScope, error) { return nil, nil })
	h.SetReceiptStores(receipts, postgres.NewIdempotencyKeyRepository(pdb))
	sealer, err := ingestpayload.NewSealer(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	jobs := postgres.NewIngestJobRepository(pdb)
	ih := &importHarness{v2Harness: v2, h: h, svc: svc,
		queue:  ingestqueue.New(jobs, postgres.NewIngestPayloadRepository(pdb), sealer),
		jp:     ingest.NewJobProcessor(v2.ingest),
		userID: shared.NewID().String(),
	}
	// The result read resolves its viewer: the harness reads as an owner.
	ih.receipts = handler.NewIngestReceiptHandler(receipts, datascope.New(postgres.NewDataScopeRepository(pdb),
		func(context.Context) datascope.Caller { return datascope.Caller{UserID: ih.userID, IsOwner: true} }, logger.NewNop()),
		logger.NewNop())
	ih.worker = controller.NewIngestWorkerController(jobs, ih.jp, &controller.IngestWorkerControllerConfig{MaxPerTick: 100})
	if _, err := v2.db.ExecContext(context.Background(), `INSERT INTO users (id, email, name) VALUES ($1, $2, 'importer')`,
		ih.userID, ih.userID+"@import.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = v2.db.ExecContext(context.Background(), `DELETE FROM ingest_jobs WHERE tenant_id = $1`, v2.tenantID)
		_, _ = v2.db.ExecContext(context.Background(), `DELETE FROM ingest_payloads WHERE tenant_id = $1`, v2.tenantID)
		_, _ = v2.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, ih.userID)
	})
	ih.wire(svc, nil)
	return ih
}

func (ih *importHarness) upload(t *testing.T, tenant, query, name string, data []byte, admin bool) (*httptest.ResponseRecorder, handler.FindingImportResponse) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("file", name)
	_, _ = w.Write(data)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports"+query, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// Each call is its own upload: a key keeps two uploads of the same
	// file (the tests repeat fixtures) from being one by their digest.
	req.Header.Set("Idempotency-Key", shared.NewID().String())
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
	ctx = context.WithValue(ctx, middleware.UserIDKey, ih.userID)
	if admin {
		ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	}
	rec := httptest.NewRecorder()
	ih.h.Import(rec, req.WithContext(ctx))
	var resp handler.FindingImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, ih.finish(t, rec, resp)
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
			// A CSV has no signature to detect: its format is named.
			format := ""
			if strings.HasSuffix(p, ".csv") {
				format = "&format=" + filepath.Base(filepath.Dir(p))
			}
			rec, resp := ih.upload(t, ih.tenantID, "?dry_run=true"+format, filepath.Base(p), data, true)
			if rec.Code != http.StatusOK || len(resp.Files) != 1 || resp.Files[0].Error != nil {
				t.Fatalf("preview %d: %s", rec.Code, rec.Body.String())
			}
			if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, ih.tenantID); n != before {
				t.Fatalf("a preview wrote %d findings", n-before)
			}
			rec, resp = ih.upload(t, ih.tenantID, strings.Replace(format, "&", "?", 1), filepath.Base(p), data, true)
			if rec.Code != http.StatusAccepted || resp.Files[0].Error != nil {
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

// An OpenVEX statement about a component inside one image requests a false
// positive (enforce, admin) only for that image's finding: not the same package's finding on
// another asset, not another tenant's, and nothing in a preview.
func TestFindingImport_VEXDocument_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveEnforce)
	ctx := context.Background()
	// A global package version (the feed's), so findings of two tenants can
	// name it; the fixture's statement names this package URL.
	_, compID := testdb.SeedPackageVersion(t, ih.db, "", "pkg:golang/example.com/libexample@v1.4.2")
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
			VALUES ($1, $2, $3, $4, 'sca', 'trivy', 'm', 'high', $5, 'new', 'CVE-2025-1111')`, id, tenant, assetID, compID, "fp-"+id.String()); err != nil {
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
	if s, v := status(web); s != "new" || v != "" {
		t.Fatalf("a preview changed the finding: %s %s", s, v)
	}

	// Without findings:approve (not admin, no permission): stored, not closed.
	rec, resp = ih.upload(t, ih.tenantID, "", "image.vex.json", doc, false)
	if rec.Code != http.StatusAccepted || resp.Files[0].VEX.Requested != 0 || resp.Files[0].VEX.Stored != 1 {
		t.Fatalf("no-approve import: %s", rec.Body.String())
	}
	if s, v := status(web); s != "new" || v != "not_affected" {
		t.Fatalf("no-approve: %s %s", s, v)
	}

	rec, resp = ih.upload(t, ih.tenantID, "", "image.vex.json", doc, true)
	if rec.Code != http.StatusAccepted || resp.Files[0].VEX.Requested != 1 {
		t.Fatalf("import: %s", rec.Body.String())
	}
	// Four-eyes: the upload requests a false positive; it does not set one.
	if s, v := status(web); s != "new" || v != "not_affected" {
		t.Fatalf("the image's finding = %s %s, want new / not_affected (a pending request, not a closure)", s, v)
	}
	var pending int
	if err := ih.db.QueryRow(`SELECT count(*) FROM finding_status_approvals WHERE tenant_id = $1 AND finding_id = $2
		AND requested_status = 'false_positive' AND requested_by_actor = 'vex' AND status = 'pending'`, ih.tenantID, web).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending vex requests = %d %v, want 1", pending, err)
	}
	if s, v := status(other); s != "new" || v != "" {
		t.Fatalf("the same package on another image changed: %s %s", s, v)
	}
	if s, v := status(foreign); s != "new" || v != "" {
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
	if rec.Code != http.StatusAccepted || len(resp.Files) != 1 || resp.Files[0].Error != nil || resp.Files[0].Format != "qualys" {
		t.Fatalf("%d: %s", rec.Code, rec.Body.String())
	}
	if resp.Files[0].Ingest == nil || resp.Files[0].Ingest.FindingsCreated == 0 {
		t.Fatalf("nothing ingested: %s", rec.Body.String())
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND tool_name = $2`, ih.tenantID, "qualys"); n == 0 {
		t.Fatal("no Qualys finding stored")
	}
}

// A committed import records its producer: the record names the tenant and
// the uploader, its findings carry the import id as scan_id and its assets
// as import_id; another tenant cannot read the record; a preview records
// nothing.
func TestFindingImport_RecordsTheProducer_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	ctx := context.Background()
	var doc []byte
	for _, p := range ctisImporterFixtures(t) {
		if strings.HasSuffix(p, filepath.Join("nessus", "scan.nessus")) {
			doc, _ = os.ReadFile(p)
		}
	}
	if doc == nil {
		t.Skip("no Nessus fixture")
	}
	user := shared.NewID()
	if _, err := ih.db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, user, user.String()+"@example.com", "Importer"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = ih.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user) })

	uploadAs := func(query string) handler.FindingImportResponse {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		w, _ := mw.CreateFormFile("file", "weekly.nessus")
		_, _ = w.Write(doc)
		_ = mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports"+query, &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		c := context.WithValue(req.Context(), middleware.TenantIDKey, ih.tenantID)
		c = context.WithValue(c, middleware.UserIDKey, user.String())
		c = context.WithValue(c, middleware.IsAdminKey, true)
		rec := httptest.NewRecorder()
		ih.h.Import(rec, req.WithContext(c))
		if want := map[bool]int{true: http.StatusOK, false: http.StatusAccepted}[strings.Contains(query, "dry_run")]; rec.Code != want {
			t.Fatalf("%d: %s", rec.Code, rec.Body.String())
		}
		var resp handler.FindingImportResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return ih.finish(t, rec, resp)
	}

	if resp := uploadAs("?dry_run=true"); resp.Files[0].ImportID != "" {
		t.Fatal("a preview returned an import id")
	}
	if n := ih.count(t, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1`, ih.tenantID); n != 0 {
		t.Fatalf("a preview wrote %d import records", n)
	}

	resp := uploadAs("")
	importID := resp.Files[0].ImportID
	if importID == "" {
		t.Fatal("no import id")
	}
	if resp.ReceiptID != importID {
		t.Fatalf("receipt id %q, file import id %q", resp.ReceiptID, importID)
	}
	repo := postgres.NewIngestReceiptRepository(&postgres.DB{DB: ih.db})
	rec, err := repo.Get(ctx, shared.MustIDFromString(ih.tenantID), shared.MustIDFromString(importID))
	if err != nil {
		t.Fatal(err)
	}
	if rec.ActorUserID == nil || *rec.ActorUserID != user || rec.Format != "nessus" || rec.Counts.Created == 0 || rec.AssetsCreated == 0 ||
		rec.SourceKind != "upload" || rec.Status != "completed" || rec.Reports != 1 || rec.Coverage != "partial" {
		t.Fatalf("record = %+v", rec)
	}
	if strings.Contains(rec.FilenameSHA256, "weekly") || len(rec.FilenameSHA256) != 64 {
		t.Fatalf("file name stored: %q", rec.FilenameSHA256)
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND scan_id = $2`, ih.tenantID, importID); n != rec.Counts.Created {
		t.Fatalf("%d findings carry the import id, want %d", n, rec.Counts.Created)
	}
	if n := ih.count(t, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND import_id = $2`, ih.tenantID, importID); n != rec.AssetsCreated {
		t.Fatalf("%d assets carry the import id, want %d", n, rec.AssetsCreated)
	}
	if _, err := repo.Get(ctx, shared.NewID(), shared.MustIDFromString(importID)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant read the import record: %v", err)
	}
}

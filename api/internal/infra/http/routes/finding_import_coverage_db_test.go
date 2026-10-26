package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// onlyScope is an uploader restricted to a fixed asset set.
type onlyScope map[shared.ID]bool

func (o onlyScope) AssetsInScope(_ context.Context, ids []shared.ID) ([]shared.ID, error) {
	var out []shared.ID
	for _, id := range ids {
		if o[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

func (ih *importHarness) uploadAs(t *testing.T, query string, perms []string, doc string) (*httptest.ResponseRecorder, handler.FindingImportResponse) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("file", "scan.nessus")
	_, _ = w.Write([]byte(doc))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports"+query, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Idempotency-Key", shared.NewID().String())
	c := context.WithValue(req.Context(), middleware.TenantIDKey, ih.tenantID)
	c = context.WithValue(c, middleware.UserIDKey, ih.userID)
	c = context.WithValue(c, middleware.FetchedPermissionsKey, perms)
	rec := httptest.NewRecorder()
	ih.h.Import(rec, req.WithContext(c))
	var resp handler.FindingImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, ih.finish(t, rec, resp)
}

// Only an upload that declares full coverage of explicit assets closes what
// it did not report, and only for an uploader who may change finding
// statuses and whose scope holds every declared asset. The receipt says
// full coverage, closed 1, untouched 0, and logs the closed finding.
func TestFindingImport_FullCoverageCloses_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	pdb := &postgres.DB{DB: ih.db}
	receipts := postgres.NewIngestReceiptRepository(pdb)
	ih.h.SetReceiptStores(receipts, postgres.NewIdempotencyKeyRepository(pdb))
	write := []string{permission.FindingsWrite.String(), permission.AssetsWrite.String(), permission.AssetsImport.String()}
	statusOnly := append(append([]string{}, write...), permission.FindingsStatus.String())
	withStatus := append(append([]string{}, statusOnly...), permission.FindingsBulkUpdate.String(), permission.FindingsVerify.String())

	if rec, _ := ih.uploadAs(t, "", write, receiptNessusFull); rec.Code != http.StatusAccepted {
		t.Fatalf("baseline %d %s", rec.Code, rec.Body.String())
	}
	var assetID string
	if err := ih.db.QueryRow(`SELECT asset_id::text FROM findings WHERE tenant_id = $1 LIMIT 1`, ih.tenantID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	full := "?coverage=full&asset_id=" + assetID
	resolved := func() int {
		return ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'resolved'`, ih.tenantID)
	}

	// Refusals change nothing.
	if rec, _ := ih.uploadAs(t, full, write, receiptNessusSubset); rec.Code != http.StatusForbidden {
		t.Fatalf("coverage=full without findings:status: %d", rec.Code)
	}
	if rec, _ := ih.uploadAs(t, full, statusOnly, receiptNessusSubset); rec.Code != http.StatusForbidden {
		t.Fatalf("coverage=full without findings:bulk_update: %d", rec.Code)
	}
	if rec, _ := ih.uploadAs(t, full+"&min_severity=high", withStatus, receiptNessusSubset); rec.Code != http.StatusBadRequest {
		t.Fatalf("coverage=full with min_severity (dropped findings would close): %d", rec.Code)
	}
	tooMany := full
	for range findingimport.MaxCoverageAssets {
		tooMany += "&asset_id=" + assetID
	}
	if rec, _ := ih.uploadAs(t, tooMany, withStatus, receiptNessusSubset); rec.Code != http.StatusBadRequest {
		t.Fatalf("more than %d asset_id values (duplicates count): %d", findingimport.MaxCoverageAssets, rec.Code)
	}
	if rec, _ := ih.uploadAs(t, "?coverage=full&asset_id="+shared.NewID().String(), withStatus, receiptNessusSubset); rec.Code != http.StatusBadRequest {
		t.Fatalf("an asset of no one: %d", rec.Code)
	}
	if rec, _ := ih.uploadAs(t, "?coverage=full", withStatus, receiptNessusSubset); rec.Code != http.StatusBadRequest {
		t.Fatalf("full coverage without a scope: %d", rec.Code)
	}
	if rec, _ := ih.uploadAs(t, "?asset_id="+assetID, withStatus, receiptNessusSubset); rec.Code != http.StatusBadRequest {
		t.Fatalf("a scope without full coverage: %d", rec.Code)
	}
	ih.h.SetActorResolver(func(context.Context, shared.ID) (ingest.ActorScope, error) { return onlyScope{}, nil })
	if rec, _ := ih.uploadAs(t, full, withStatus, receiptNessusSubset); rec.Code != http.StatusBadRequest {
		t.Fatalf("an asset outside the uploader's scope: %d", rec.Code)
	}
	ih.h.SetActorResolver(func(context.Context, shared.ID) (ingest.ActorScope, error) { return nil, nil })
	if n := resolved(); n != 0 {
		t.Fatalf("a refused upload closed %d findings", n)
	}

	// The same asset named twice is one asset.
	rec, resp := ih.uploadAs(t, full+"&asset_id="+assetID, withStatus, receiptNessusSubset)
	if rec.Code != http.StatusAccepted || resp.Receipt == nil {
		t.Fatalf("full-coverage upload %d %s", rec.Code, rec.Body.String())
	}
	r := resp.Receipt
	if r.Coverage.Type != "full" || r.Coverage.Note != "resolved" || r.Counts.Closed != 1 || r.Counts.Updated != 1 ||
		r.Counts.Untouched == nil || *r.Counts.Untouched != 0 {
		t.Fatalf("receipt = %+v", r)
	}
	if n := resolved(); n != 1 {
		t.Fatalf("%d findings closed, want 1", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM finding_ingest_actions WHERE tenant_id = $1 AND receipt_id = $2 AND action = 'closed'`,
		ih.tenantID, r.ID); n != 1 {
		t.Fatalf("%d closed action rows", n)
	}
}

// A declared asset must be visible to the uploader, not only writable: an
// administrator who is not a member of a private program writes anywhere
// (unrestricted import) but may not close the findings of that program's
// asset by naming it, and the answer is the one for an unknown asset.
func TestFindingImport_FullCoverageHiddenAsset_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	pdb := &postgres.DB{DB: ih.db}
	receipts := postgres.NewIngestReceiptRepository(pdb)
	admin := shared.NewID().String()
	enforcer := datascope.New(postgres.NewDataScopeRepository(pdb), func(context.Context) datascope.Caller {
		return datascope.Caller{UserID: admin, IsAdmin: true}
	}, logger.NewNop())
	svc := findingimport.NewService(ih.ingest, postgres.NewFindingRepository(pdb), receipts, ingest.SourceResolveDryRun, logger.NewNop())
	ih.h = handler.NewFindingImportHandler(svc, enforcer, nil, logger.NewNop())
	ih.h.SetReceiptStores(receipts, postgres.NewIdempotencyKeyRepository(pdb))
	ih.wire(svc, findingimport.DataScopeResolver(enforcer))

	program, hidden, open := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO bounty_programs (id, tenant_id, name, terms_sha256, visibility) VALUES ($1, $2, 'cov-p', repeat('a', 64), 'private')`, []any{program, ih.tenantID}},
		{`INSERT INTO assets (id, tenant_id, name, asset_type, program_only) VALUES ($1, $2, 'cov-p.example.com', 'domain', TRUE)`, []any{hidden, ih.tenantID}},
		{`INSERT INTO asset_program_links (tenant_id, asset_id, program_id, source) VALUES ($1, $2, $3, 'program_manual')`, []any{ih.tenantID, hidden, program}},
		{`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'cov-open.example.com', 'domain')`, []any{open, ih.tenantID}},
	} {
		if _, err := ih.db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = ih.db.Exec(`DELETE FROM asset_program_links WHERE tenant_id = $1`, ih.tenantID)
		_, _ = ih.db.Exec(`DELETE FROM bounty_programs WHERE tenant_id = $1`, ih.tenantID)
	})
	perms := []string{permission.FindingsWrite.String(), permission.AssetsWrite.String(), permission.AssetsImport.String(),
		permission.FindingsStatus.String(), permission.FindingsBulkUpdate.String(), permission.FindingsVerify.String()}

	rec, _ := ih.uploadAs(t, "?coverage=full&asset_id="+hidden, perms, receiptNessusSubset)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a private program asset hidden from the uploader was accepted: %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := ih.uploadAs(t, "?coverage=full&asset_id="+open, perms, receiptNessusSubset); rec.Code != http.StatusAccepted {
		t.Fatalf("a visible asset: %d %s", rec.Code, rec.Body.String())
	}
}

// Absence is decided from the upload's receipt, not from scan_id: concurrent
// full-coverage uploads of one scope that all report the same finding never
// close it (each overwrote the others' scan_id), and a finding with an action
// row on the receipt stays open whatever its scan_id says. A receipt past
// its action cap closes nothing.
func TestFindingImport_FullCoverageConcurrentUploads_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	pdb := &postgres.DB{DB: ih.db}
	ih.h.SetReceiptStores(postgres.NewIngestReceiptRepository(pdb), postgres.NewIdempotencyKeyRepository(pdb))
	perms := []string{permission.FindingsWrite.String(), permission.AssetsWrite.String(), permission.AssetsImport.String(),
		permission.FindingsStatus.String(), permission.FindingsBulkUpdate.String(), permission.FindingsVerify.String()}

	if rec, _ := ih.uploadAs(t, "", perms, receiptNessusFull); rec.Code != http.StatusAccepted {
		t.Fatalf("baseline %d %s", rec.Code, rec.Body.String())
	}
	var assetID string
	if err := ih.db.QueryRow(`SELECT asset_id::text FROM findings WHERE tenant_id = $1 LIMIT 1`, ih.tenantID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	full := "?coverage=full&asset_id=" + assetID

	const uploads = 6
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, uploads)
	for i := range uploads {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec, _ := ih.uploadAs(t, full, perms, receiptNessusSubset)
			codes[i] = rec.Code
		}(i)
	}
	close(start)
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusAccepted {
			t.Errorf("upload %d: %d", i, c)
		}
	}
	// The subset reports plugin 1001 only: it must stay open; the other
	// finding of the full report is closed.
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'resolved' AND rule_id = '1001'`, ih.tenantID); n != 0 {
		t.Fatalf("a finding every concurrent upload reported was closed (%d)", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'resolved'`, ih.tenantID); n != 1 {
		t.Fatalf("%d findings closed, want the 1 no upload reported", n)
	}

	// Repository level: the action row decides, not scan_id.
	ctx := context.Background()
	repo := postgres.NewFindingRepository(pdb)
	tenant, _ := shared.IDFromString(ih.tenantID)
	asset, _ := shared.IDFromString(assetID)
	var receiptStr, tool string
	if err := ih.db.QueryRow(`SELECT a.receipt_id::text, f.tool_name FROM finding_ingest_actions a JOIN findings f ON f.id = a.finding_id
		WHERE a.tenant_id = $1 AND f.rule_id = '1001' AND a.action = 'still_detected' LIMIT 1`, ih.tenantID).Scan(&receiptStr, &tool); err != nil {
		t.Fatal(err)
	}
	receipt, _ := shared.IDFromString(receiptStr)
	if _, err := ih.db.Exec(`UPDATE findings SET scan_id = 'another-upload' WHERE tenant_id = $1 AND rule_id = '1001'`, ih.tenantID); err != nil {
		t.Fatal(err)
	}
	stale, open, err := repo.ImportCoverageCandidates(ctx, tenant, []shared.ID{asset}, tool, receipt)
	if err != nil || len(stale) != 0 || open != 1 {
		t.Fatalf("candidates = %v open %d err %v; want none (the finding has an action row) and 1 open", stale, open, err)
	}
	if _, err := ih.db.Exec(`UPDATE ingest_receipts SET actions_truncated = true WHERE id = $1`, receiptStr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ImportCoverageCandidates(ctx, tenant, []shared.ID{asset}, tool, receipt); !errors.Is(err, ingestreport.ErrReceiptIncomplete) {
		t.Fatalf("truncated receipt: err %v, want ErrReceiptIncomplete", err)
	}
	// Another tenant cannot use this receipt.
	if _, _, err := repo.ImportCoverageCandidates(ctx, shared.NewID(), []shared.ID{asset}, tool, receipt); !errors.Is(err, ingestreport.ErrReceiptIncomplete) {
		t.Fatalf("cross-tenant receipt: err %v, want ErrReceiptIncomplete", err)
	}
}

// Closing by absence is a verification of a fix: an uploader without
// findings:verify has the file imported and closes nothing (receipt note
// needs_verify), a critical or known-exploited finding stays open, and a
// finding whose latest sighting came from a platform sensor stays open. The
// last case closes once none of those holds.
func TestFindingImport_FullCoverageClosureGuards_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	pdb := &postgres.DB{DB: ih.db}
	ih.h.SetReceiptStores(postgres.NewIngestReceiptRepository(pdb), postgres.NewIdempotencyKeyRepository(pdb))
	write := []string{permission.FindingsWrite.String(), permission.AssetsWrite.String(), permission.AssetsImport.String(),
		permission.FindingsStatus.String(), permission.FindingsBulkUpdate.String()}
	withVerify := append(append([]string{}, write...), permission.FindingsVerify.String())

	if rec, _ := ih.uploadAs(t, "", write, receiptNessusFull); rec.Code != http.StatusAccepted {
		t.Fatalf("baseline %d %s", rec.Code, rec.Body.String())
	}
	var assetID string
	if err := ih.db.QueryRow(`SELECT asset_id::text FROM findings WHERE tenant_id = $1 LIMIT 1`, ih.tenantID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	full := "?coverage=full&asset_id=" + assetID
	// The subset reports plugin 1001; 1002 is the one an upload may close.
	attempt := func(perms []string) handler.FindingImportResponse {
		t.Helper()
		rec, resp := ih.uploadAs(t, full, perms, receiptNessusSubset)
		if rec.Code != http.StatusAccepted || resp.Receipt == nil {
			t.Fatalf("upload %d %s", rec.Code, rec.Body.String())
		}
		return resp
	}
	closed := func() int {
		return ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = '1002' AND status = 'resolved'`, ih.tenantID)
	}
	reopen := func() {
		if _, err := ih.db.Exec(`UPDATE findings SET status = 'new', resolved_at = NULL, resolution = NULL, closure_reason = NULL, verification = NULL
			WHERE tenant_id = $1 AND rule_id = '1002'`, ih.tenantID); err != nil {
			t.Fatal(err)
		}
	}

	// No findings:verify: imported, nothing closed, the receipt says why.
	resp := attempt(write)
	if resp.Receipt.Coverage.Note != "needs_verify" || resp.Receipt.Coverage.Type != "partial" || closed() != 0 {
		t.Fatalf("without findings:verify: receipt %+v, closed %d", resp.Receipt.Coverage, closed())
	}
	if n := ih.count(t, `SELECT count(*) FROM finding_ingest_actions a JOIN findings f ON f.id = a.finding_id
		WHERE a.receipt_id = $1 AND f.rule_id = '1001'`, resp.Receipt.ID); n != 1 {
		t.Fatalf("the file was not imported: %d action rows for the reported finding", n)
	}

	// Critical and known-exploited findings stay open.
	for _, set := range []string{`severity = 'critical'`, `is_in_kev = true`} {
		if _, err := ih.db.Exec(`UPDATE findings SET `+set+` WHERE tenant_id = $1 AND rule_id = '1002'`, ih.tenantID); err != nil {
			t.Fatal(err)
		}
		if attempt(withVerify); closed() != 0 {
			t.Fatalf("a finding with %s was closed by an upload", set)
		}
	}
	if _, err := ih.db.Exec(`UPDATE findings SET severity = 'medium', is_in_kev = false WHERE tenant_id = $1 AND rule_id = '1002'`, ih.tenantID); err != nil {
		t.Fatal(err)
	}

	// A finding a sensor sighted after the last upload stays open.
	receipt := shared.NewID().String()
	if _, err := ih.db.Exec(`INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref) VALUES ($1::uuid, $2, 'command', $1::text)`, receipt, ih.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := ih.db.Exec(`INSERT INTO finding_ingest_actions (tenant_id, receipt_id, finding_id, action)
		SELECT tenant_id, $1, id, 'still_detected' FROM findings WHERE tenant_id = $2 AND rule_id = '1002'`, receipt, ih.tenantID); err != nil {
		t.Fatal(err)
	}
	if attempt(withVerify); closed() != 0 {
		t.Fatal("a finding last sighted by a platform sensor was closed by an upload")
	}
	if _, err := ih.db.Exec(`DELETE FROM ingest_receipts WHERE id = $1`, receipt); err != nil {
		t.Fatal(err)
	}

	// None of the guards applies: it closes.
	if resp := attempt(withVerify); resp.Receipt.Coverage.Note != "resolved" || closed() != 1 {
		t.Fatalf("control: receipt %+v, closed %d", resp.Receipt.Coverage, closed())
	}
	reopen()
}

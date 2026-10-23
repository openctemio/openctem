package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
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
	c := context.WithValue(req.Context(), middleware.TenantIDKey, ih.tenantID)
	c = context.WithValue(c, middleware.FetchedPermissionsKey, perms)
	rec := httptest.NewRecorder()
	ih.h.Import(rec, req.WithContext(c))
	var resp handler.FindingImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp
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
	withStatus := append(append([]string{}, statusOnly...), permission.FindingsBulkUpdate.String())

	if rec, _ := ih.uploadAs(t, "", write, receiptNessusFull); rec.Code != http.StatusCreated {
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
	if rec.Code != http.StatusCreated || resp.Receipt == nil {
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
		permission.FindingsStatus.String(), permission.FindingsBulkUpdate.String()}

	rec, _ := ih.uploadAs(t, "?coverage=full&asset_id="+hidden, perms, receiptNessusSubset)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a private program asset hidden from the uploader was accepted: %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := ih.uploadAs(t, "?coverage=full&asset_id="+open, perms, receiptNessusSubset); rec.Code != http.StatusCreated {
		t.Fatalf("a visible asset: %d %s", rec.Code, rec.Body.String())
	}
}

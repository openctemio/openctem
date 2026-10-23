package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// uploadPlain posts a committed upload without an Idempotency-Key.
func (ih *importHarness) uploadPlain(t *testing.T, name, doc string) (*httptest.ResponseRecorder, handler.FindingImportResponse) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("file", name)
	_, _ = w.Write([]byte(doc))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c := context.WithValue(req.Context(), middleware.TenantIDKey, ih.tenantID)
	c = context.WithValue(c, middleware.UserIDKey, ih.userID)
	rec := httptest.NewRecorder()
	ih.h.Import(rec, req.WithContext(c))
	var resp handler.FindingImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp
}

// A committed upload is stored sealed and answered 202 before anything is
// imported; the worker imports it and deletes what it stored. The same files
// from the same caller again within the digest window, without a key, are
// that upload.
func TestFindingImport_AcceptedThenImported_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	rec, first := ih.uploadPlain(t, "full.nessus", receiptNessusFull)
	if rec.Code != http.StatusAccepted || first.Status != "queued" || first.ReceiptID == "" {
		t.Fatalf("accept %d: %s", rec.Code, rec.Body.String())
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, ih.tenantID); n != 0 {
		t.Fatalf("%d findings written in the request", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1 AND id = $2 AND status = 'queued'`, ih.tenantID, first.ReceiptID); n != 1 {
		t.Fatal("the receipt is not queued")
	}
	var sealed []byte
	if err := ih.db.QueryRow(`SELECT sealed FROM ingest_payloads WHERE tenant_id = $1`, ih.tenantID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("NessusClientData")) {
		t.Fatal("the upload is stored in plaintext")
	}
	if n := ih.count(t, `SELECT count(*) FROM ingest_payloads WHERE tenant_id = $1`, ih.tenantID); n != 1 {
		t.Fatalf("%d stored parts, want 1", n)
	}

	rec2, second := ih.uploadPlain(t, "renamed.nessus", receiptNessusFull)
	if rec2.Code != http.StatusAccepted || second.ReceiptID != first.ReceiptID || rec2.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("the same files again: %d %s", rec2.Code, rec2.Body.String())
	}
	if n := ih.count(t, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1`, ih.tenantID); n != 1 {
		t.Fatalf("%d receipts for one upload", n)
	}

	res := ih.finish(t, rec, first)
	if res.Status != "applied" || len(res.Files) != 1 || res.Files[0].Ingest == nil || res.Files[0].Ingest.FindingsCreated != 2 ||
		res.Receipt == nil || res.Receipt.Status != "completed" {
		t.Fatalf("result = %+v", res)
	}
	if n := ih.count(t, `SELECT count(*) FROM ingest_payloads WHERE tenant_id = $1`, ih.tenantID); n != 0 {
		t.Fatalf("%d stored parts left after the import", n)
	}
}

// The result of another tenant's upload is 404.
func TestFindingImport_ResultOfAnotherTenant_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	rec, first := ih.uploadPlain(t, "full.nessus", receiptNessusFull)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("accept %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/imports/"+first.ReceiptID+"/result", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", first.ReceiptID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, shared.NewID().String())
	w := httptest.NewRecorder()
	ih.receipts.Result(w, req.WithContext(ctx))
	if w.Code != http.StatusNotFound {
		t.Fatalf("another tenant read the result: %d %s", w.Code, w.Body.String())
	}
}

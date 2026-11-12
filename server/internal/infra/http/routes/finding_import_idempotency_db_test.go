package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/idempotency"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// downStore is an Idempotency-Key store that cannot be reached.
type downStore struct{}

func (downStore) Claim(context.Context, idempotency.Scope, time.Duration) (*idempotency.Claim, *idempotency.Record, error) {
	return nil, nil, errors.New("connection refused")
}
func (downStore) Complete(context.Context, *idempotency.Claim, string, int, []byte, *shared.ID) error {
	return errors.New("connection refused")
}
func (downStore) Release(context.Context, *idempotency.Claim) error {
	return errors.New("connection refused")
}

func (ih *importHarness) uploadKeyed(t *testing.T, user, key, name, doc string) (*httptest.ResponseRecorder, handler.FindingImportResponse) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf) // a new random boundary every call
	w, _ := mw.CreateFormFile("file", name)
	_, _ = w.Write([]byte(doc))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if key != "" {
		req.Header.Set(idempotency.Header, key)
	}
	c := context.WithValue(req.Context(), middleware.TenantIDKey, ih.tenantID)
	c = context.WithValue(c, middleware.UserIDKey, user)
	c = context.WithValue(c, middleware.IsAdminKey, true)
	rec := httptest.NewRecorder()
	ih.h.Import(rec, req.WithContext(c))
	var resp handler.FindingImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Header().Get("Idempotent-Replayed") == "true" {
		return rec, resp
	}
	return rec, ih.finish(t, rec, resp)
}

// Idempotency-Key on an upload: a retry of the same file (another multipart
// boundary, another file name) replays the first answer with the same
// receipt and imports nothing; the same key with another file is 422;
// another member's identical key is their own; a key store that cannot be
// reached refuses the upload (503) before anything is imported.
func TestFindingImport_IdempotencyKey_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	pdb := &postgres.DB{DB: ih.db}
	receipts := postgres.NewIngestReceiptRepository(pdb)
	ih.h.SetReceiptStores(receipts, postgres.NewIdempotencyKeyRepository(pdb))
	userA, userB := shared.NewID().String(), shared.NewID().String()
	for _, u := range []string{userA, userB} {
		if _, err := ih.db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'idem')`, u, u+"@idem.test"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = ih.db.Exec(`DELETE FROM ingest_receipts WHERE tenant_id = $1`, ih.tenantID)
		_, _ = ih.db.Exec(`DELETE FROM users WHERE id = ANY($1)`, "{"+userA+","+userB+"}")
	})
	countReceipts := func() int {
		return ih.count(t, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1`, ih.tenantID)
	}

	rec, first := ih.uploadKeyed(t, userA, "ci-run-42", "full.nessus", receiptNessusFull)
	if rec.Code != http.StatusAccepted || first.Receipt == nil || first.Receipt.Counts.Created != 2 ||
		rec.Header().Get("Location") != "/api/v1/findings/imports/"+first.ReceiptID {
		t.Fatalf("first upload %d %s (location %q)", rec.Code, rec.Body.String(), rec.Header().Get("Location"))
	}
	rec, again := ih.uploadKeyed(t, userA, "ci-run-42", "renamed.nessus", receiptNessusFull)
	if rec.Code != http.StatusAccepted || rec.Header().Get("Idempotent-Replayed") != "true" || again.ReceiptID != first.ReceiptID ||
		rec.Header().Get("Location") != "/api/v1/findings/imports/"+first.ReceiptID {
		t.Fatalf("retry %d %s", rec.Code, rec.Body.String())
	}
	if n := countReceipts(); n != 1 {
		t.Fatalf("a replayed upload made %d receipts", n)
	}
	if r, _ := receipts.Get(context.Background(), shared.MustIDFromString(ih.tenantID), shared.MustIDFromString(first.ReceiptID)); r.Reports != 1 {
		t.Fatalf("the replay ingested again: reports %d", r.Reports)
	}

	rec, _ = ih.uploadKeyed(t, userA, "ci-run-42", "full.nessus", receiptNessusSubset)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("key reused with another file: %d %s", rec.Code, rec.Body.String())
	}
	rec, other := ih.uploadKeyed(t, userB, "ci-run-42", "full.nessus", receiptNessusFull)
	if rec.Code != http.StatusAccepted || rec.Header().Get("Idempotent-Replayed") != "" || other.ReceiptID == first.ReceiptID {
		t.Fatalf("another member's key replayed the first member's import: %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := ih.uploadKeyed(t, userA, "bad key", "full.nessus", receiptNessusFull); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid key: %d", rec.Code)
	}

	before := countReceipts()
	ih.h.SetReceiptStores(receipts, downStore{})
	rec, _ = ih.uploadKeyed(t, userA, "ci-run-43", "full.nessus", receiptNessusFull)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("store down: %d %s", rec.Code, rec.Body.String())
	}
	if n := countReceipts(); n != before {
		t.Fatalf("an upload was imported while the key store was down (%d receipts, had %d)", n, before)
	}
	// Without a key the store is not needed.
	if rec, _ := ih.uploadKeyed(t, userA, "", "full.nessus", receiptNessusFull); rec.Code != http.StatusAccepted {
		t.Fatalf("upload without a key: %d", rec.Code)
	}
}

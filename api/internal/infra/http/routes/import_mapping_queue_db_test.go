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

	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An upload through an import mapping is accepted with the version resolved
// at that moment and applied by the worker with exactly that version, in
// the job's organization (docs/rfcs/RFC-126-import-mappings.md,
// docs/rfcs/RFC-122-ingest-receipts.md).

// accept sends an import and leaves it queued (no worker run).
func (m *mappingHarness) accept(t *testing.T, tenant, query string, data []byte) handler.FindingImportResponse {
	t.Helper()
	return m.acceptKeyed(t, tenant, query, data, shared.NewID().String())
}

// acceptKeyed is accept with a chosen Idempotency-Key ("" sends none).
func (m *mappingHarness) acceptKeyed(t *testing.T, tenant, query string, data []byte, key string) handler.FindingImportResponse {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("file", "export.csv")
	_, _ = w.Write(data)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports"+query, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
	ctx = context.WithValue(ctx, middleware.UserIDKey, m.userID)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	rec := httptest.NewRecorder()
	m.h.Import(rec, req.WithContext(ctx))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body)
	}
	var resp handler.FindingImportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func (m *mappingHarness) drain(t *testing.T) {
	t.Helper()
	if _, err := m.worker.Reconcile(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

func (m *mappingHarness) createMapping(t *testing.T, tenant, name string) string {
	t.Helper()
	rec, out := m.call(t, tenant, m.mh.Create, http.MethodPost, "/", jsonBody(t, map[string]any{"name": name, "mapping": json.RawMessage(dbMappingDoc)}), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", name, rec.Code, rec.Body)
	}
	return out["mapping"].(map[string]any)["id"].(string)
}

// jobOutcome is the job's state and fixed public error for a receipt.
func (m *mappingHarness) jobOutcome(t *testing.T, receiptID string) (status, code string) {
	t.Helper()
	var pe *string
	if err := m.db.QueryRow(`SELECT status, public_error FROM ingest_jobs WHERE tenant_id = $1 AND source_ref = $2`,
		m.tenant, receiptID).Scan(&status, &pe); err != nil {
		t.Fatal(err)
	}
	if pe != nil {
		code = *pe
	}
	return status, code
}

func TestImportMapping_QueuedUploadAppliesThePinnedVersion_DB(t *testing.T) {
	m := newMappingHarness(t)
	id := m.createMapping(t, m.tenant, "pinned-vm")
	p := map[string]string{"id": id}
	csv := []byte("title,severity,host,note\nOpenSSL out of date,High,web-01.example.com,upgrade\n")

	// Accepted against version 1.
	resp := m.accept(t, m.tenant, "?format=mapping:pinned-vm", csv)

	// A newer version (same identity, every finding critical) is published
	// before the worker runs.
	v2 := strings.Replace(dbMappingDoc, `"severity": {"path": "/severity", "lower": true}`, `"severity": {"const": "critical"}`, 1)
	if rec, _ := m.call(t, m.tenant, m.mh.AddVersion, http.MethodPost, "/", jsonBody(t, map[string]any{"mapping": json.RawMessage(v2)}), p); rec.Code != http.StatusCreated {
		t.Fatalf("v2: %d %s", rec.Code, rec.Body)
	}
	m.drain(t)

	if st, code := m.jobOutcome(t, resp.ReceiptID); st != "completed" || code != "" {
		t.Fatalf("job %s %q", st, code)
	}
	var sev string
	if err := m.db.QueryRow(`SELECT severity FROM findings WHERE tenant_id = $1`, m.tenant).Scan(&sev); err != nil || sev != "high" {
		t.Fatalf("severity %q (%v): the pinned version 1 maps the file's severity", sev, err)
	}
	if n := m.count(t, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1 AND format = 'mapping:pinned-vm@1'`, m.tenant); n != 1 {
		t.Fatalf("receipt format: %d rows with @1", n)
	}

	// A new upload picks up the newer version.
	m.accept(t, m.tenant, "?format=mapping:pinned-vm", []byte("title,severity,host,note\nWeak TLS,low,web-02.example.com,\n"))
	m.drain(t)
	if n := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND severity = 'critical'`, m.tenant); n != 1 {
		t.Fatalf("version 2 findings: %d", n)
	}
}

func TestImportMapping_QueuedUploadOfADeletedMappingFails_DB(t *testing.T) {
	m := newMappingHarness(t)
	id := m.createMapping(t, m.tenant, "doomed-vm")
	resp := m.accept(t, m.tenant, "?format=mapping:doomed-vm", []byte("title,severity,host,note\nX,high,web-03.example.com,\n"))
	if rec, _ := m.call(t, m.tenant, m.mh.Delete, http.MethodDelete, "/", nil, map[string]string{"id": id}); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	m.drain(t)
	if st, code := m.jobOutcome(t, resp.ReceiptID); st != "dead" || code != findingimport.ImportErrorMappingGone {
		t.Fatalf("job %s %q, want dead %s", st, code, findingimport.ImportErrorMappingGone)
	}
	if n := m.count(t, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1 AND status = 'failed'`, m.tenant); n != 1 {
		t.Fatalf("failed receipts: %d", n)
	}
	if n := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, m.tenant); n != 0 {
		t.Fatalf("findings from a deleted mapping: %d", n)
	}
}

// The worker resolves the pin in the job's organization only: a pin that
// names another organization's mapping (here forced into the envelope, which
// accept never produces) is refused, never applied there.
func TestImportMapping_QueuedPinOfAnotherOrganizationIsRefused_DB(t *testing.T) {
	m := newMappingHarness(t)
	otherID := m.createMapping(t, m.other, "foreign-vm")
	ctx := context.Background()
	csv := []byte("title,severity,host,note\nX,high,web-04.example.com,\n")
	for name, pin := range map[string]findingimport.MappingPin{
		"another organization's mapping": {ID: otherID, Format: "mapping:foreign-vm@1"},
		"an unknown id":                  {ID: shared.NewID().String(), Format: "mapping:foreign-vm@1"},
		"no version":                     {ID: otherID, Format: "mapping:foreign-vm"},
	} {
		t.Run(name, func(t *testing.T) {
			jobID := shared.NewID()
			if err := m.svc.StagePart(ctx, shared.MustIDFromString(m.tenant), jobID, 0, "export.csv", csv); err != nil {
				t.Fatal(err)
			}
			pin := pin
			uid := shared.MustIDFromString(m.userID)
			acc, err := m.svc.CommitUpload(ctx, shared.MustIDFromString(m.tenant), &uid, jobID, "test:"+jobID.String(), []byte(jobID.String()), true, "export.csv",
				findingimport.Envelope{SessionID: "pin-" + jobID.String(), Caller: findingimport.Caller{UserID: m.userID, IsAdmin: true},
					Parts: []findingimport.EnvelopePart{{Part: 0, Name: "export.csv"}}, Mapping: &pin})
			if err != nil {
				t.Fatal(err)
			}
			m.drain(t)
			if st, code := m.jobOutcome(t, acc.ReceiptID.String()); st != "dead" || code != findingimport.ImportErrorMappingGone {
				t.Fatalf("job %s %q", st, code)
			}
		})
	}
	for _, tid := range []string{m.tenant, m.other} {
		if n := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`, tid); n != 0 {
			t.Fatalf("findings in %s: %d", tid, n)
		}
	}
}

// Without an Idempotency-Key the dedup digest alone decides whether an
// upload is a repeat. It covers the pinned mapping version, so the same
// body and query after a new version is published is a new upload whose
// findings come from that version.
func TestImportMapping_SameBodyAfterNewVersionIsANewUpload_DB(t *testing.T) {
	m := newMappingHarness(t)
	id := m.createMapping(t, m.tenant, "pinned-vm")
	p := map[string]string{"id": id}
	csv := []byte("title,severity,host,note\nOpenSSL out of date,High,web-01.example.com,upgrade\n")

	first := m.acceptKeyed(t, m.tenant, "?format=mapping:pinned-vm", csv, "")
	if again := m.acceptKeyed(t, m.tenant, "?format=mapping:pinned-vm", csv, ""); again.ReceiptID != first.ReceiptID {
		t.Fatalf("same body, same version must replay the receipt: %s vs %s", again.ReceiptID, first.ReceiptID)
	}
	m.drain(t)

	v2 := strings.Replace(dbMappingDoc, `"severity": {"path": "/severity", "lower": true}`, `"severity": {"const": "critical"}`, 1)
	if rec, _ := m.call(t, m.tenant, m.mh.AddVersion, http.MethodPost, "/", jsonBody(t, map[string]any{"mapping": json.RawMessage(v2)}), p); rec.Code != http.StatusCreated {
		t.Fatalf("v2: %d %s", rec.Code, rec.Body)
	}
	second := m.acceptKeyed(t, m.tenant, "?format=mapping:pinned-vm", csv, "")
	if second.ReceiptID == first.ReceiptID {
		t.Fatalf("a new version must be a new receipt: %s vs %s", second.ReceiptID, first.ReceiptID)
	}
	m.drain(t)
	if n := m.count(t, `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1 AND format = 'mapping:pinned-vm@2'`, m.tenant); n != 1 {
		t.Fatalf("receipts on @2: %d", n)
	}
	if n := m.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND severity = 'critical'`, m.tenant); n != 1 {
		t.Fatalf("version 2 findings: %d", n)
	}
}

// A dry-run preview through a mapping parses the file with the mapping's
// resolved format, not the raw "mapping:..." selector.
func TestImportMapping_DryRunUsesTheResolvedFormat_DB(t *testing.T) {
	m := newMappingHarness(t)
	m.createMapping(t, m.tenant, "pinned-vm")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("file", "export.csv")
	_, _ = w.Write([]byte("title,severity,host,note\nOpenSSL out of date,High,web-01.example.com,upgrade\n"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports?dry_run=true&format=mapping:pinned-vm", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, m.tenant)
	ctx = context.WithValue(ctx, middleware.UserIDKey, m.userID)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	rec := httptest.NewRecorder()
	m.h.Import(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	var resp handler.FindingImportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Files) != 1 || resp.Files[0].Stats.Findings != 1 || resp.Files[0].Format != "mapping:pinned-vm@1" {
		t.Fatalf("preview: %s", rec.Body)
	}
}

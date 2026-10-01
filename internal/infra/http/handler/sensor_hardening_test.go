package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// A lost claim / already-finished command is a 409, not a 500.
func TestCommandHandler_ConflictMapsTo409(t *testing.T) {
	h := &CommandHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.handleServiceError(rec, shared.NewDomainError("CONFLICT", "command already claimed by another agent", shared.ErrConflict))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "already claimed") {
		t.Errorf("expected the domain message, got %s", rec.Body.String())
	}
}

// The adapter's raw error (parser internals / payload fragments) must not be
// echoed to the client.
func TestIngestScan_AdapterErrorIsGeneric(t *testing.T) {
	h := NewIngestHandler(nil, nil, logger.NewNop())
	tid := shared.NewID()
	agt := &agent.Agent{ID: shared.NewID(), TenantID: &tid, Status: agent.AgentStatusActive}

	body, _ := json.Marshal(map[string]any{
		"scanner_type": "no-such-scanner-SECRET-MARKER",
		"data":         json.RawMessage(`{"x":1}`),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agent/ingest/scan", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), agentContextKey, agt))
	rec := httptest.NewRecorder()
	h.IngestScan(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SECRET-MARKER") || strings.Contains(rec.Body.String(), "supported:") {
		t.Fatalf("adapter error leaked to client: %s", rec.Body.String())
	}
}

// A platform agent (no tenant) calling /agent/credentials/ingest gets a clean
// 403 instead of a MustGetTenantID panic (recovered as a 500).
func TestCredentialImport_NoTenantIs403NotPanic(t *testing.T) {
	h := &CredentialImportHandler{logger: logger.NewNop()}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agent/credentials/ingest", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("handler panicked: %v", p)
		}
	}()
	h.Import(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

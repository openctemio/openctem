package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// conflictAuditRepo refuses every rebaseline, as the repository does when the
// chain moved while the rebaseline ran.
type conflictAuditRepo struct{ fakeAuditRepo }

func (m *conflictAuditRepo) ApplyChainRebaseline(_ context.Context, _ auditdom.ChainRebaseline) error {
	return auditdom.ErrChainRebaselineConflict
}

func doRebaseline(t *testing.T, repo auditdom.Repository, tenantID, userID string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewAuditHandler(audit.NewAuditService(repo, logger.NewNop()), nil, logger.NewNop())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit-logs/rebaseline", nil)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	rec := httptest.NewRecorder()
	h.RebaselineChain(rec, req.WithContext(ctx))
	return rec
}

func TestAuditHandler_RebaselineChain_ResponseAndAuditEvent(t *testing.T) {
	repo := &fakeAuditRepo{}
	tenantID := shared.NewID().String()
	userID := shared.NewID().String()

	rec := doRebaseline(t, repo, tenantID, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"ok", "rebaseline_id", "entries_total", "entries_rewritten"} {
		if _, ok := body[k]; !ok {
			t.Errorf("response is missing %q: %v", k, body)
		}
	}
	if body["ok"] != true {
		t.Errorf("ok = %v, want true", body["ok"])
	}

	var found bool
	for _, l := range repo.logs {
		if l.Action() != auditdom.ActionAuditChainRebaselined {
			continue
		}
		found = true
		if l.ActorID() == nil || l.ActorID().String() != userID {
			t.Errorf("event actor = %v, want %s", l.ActorID(), userID)
		}
		if l.TenantID() == nil || l.TenantID().String() != tenantID {
			t.Errorf("event tenant = %v, want %s", l.TenantID(), tenantID)
		}
		if l.ResourceID() != body["rebaseline_id"] {
			t.Errorf("event resource = %s, want the rebaseline id %v", l.ResourceID(), body["rebaseline_id"])
		}
	}
	if !found {
		t.Fatalf("no %s audit event was written", auditdom.ActionAuditChainRebaselined)
	}
}

func TestAuditHandler_RebaselineChain_ConflictIs409(t *testing.T) {
	repo := &conflictAuditRepo{}
	rec := doRebaseline(t, repo, shared.NewID().String(), shared.NewID().String())
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
}

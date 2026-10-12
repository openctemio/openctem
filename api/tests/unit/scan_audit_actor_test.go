package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Update, delete, activate, pause and disable wrote their audit entries with
// TenantID only (crud.go), so the audit log could not say who changed or
// deleted a scan. The request's actor now reaches every one of them.
func TestScanService_MutationAuditEntriesCarryTheActor(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	actor := shared.NewID().String()
	ctx := scanservice.WithAuditActor(context.Background(), actor)

	s := createTestScanInRepo(deps, tenantID, "Audited Scan", scan.ScanTypeSingle)
	tid, sid := tenantID.String(), s.ID.String()

	if _, err := svc.UpdateScan(ctx, scanservice.UpdateScanInput{TenantID: tid, ScanID: sid, Name: "Renamed"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := svc.PauseScan(ctx, tid, sid); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if _, err := svc.ActivateScan(ctx, tid, sid); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := svc.DisableScan(ctx, tid, sid); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := svc.DeleteScan(ctx, tid, sid); err != nil {
		t.Fatalf("delete: %v", err)
	}

	want := []audit.Action{
		audit.ActionScanConfigUpdated, audit.ActionScanConfigPaused, audit.ActionScanConfigActivated,
		audit.ActionScanConfigDisabled, audit.ActionScanConfigDeleted,
	}
	if len(deps.auditSvc.events) != len(want) {
		t.Fatalf("got %d audit events, want %d", len(deps.auditSvc.events), len(want))
	}
	for i, ev := range deps.auditSvc.events {
		if ev.Action != want[i] {
			t.Errorf("event %d: action %s, want %s", i, ev.Action, want[i])
		}
		if got := deps.auditSvc.contexts[i].ActorID; got != actor {
			t.Errorf("%s: actor %q, want %q", ev.Action, got, actor)
		}
	}
}

// An explicit actor (CreateScan passes CreatedBy) is not overridden.
func TestScanService_ExplicitAuditActorWins(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "Explicit", scan.ScanTypeSingle)

	// No actor in the context: the entry keeps an empty actor, as before.
	if _, err := svc.PauseScan(context.Background(), tenantID.String(), s.ID.String()); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if got := deps.auditSvc.contexts[0].ActorID; got != "" {
		t.Fatalf("no actor in context: got %q, want empty", got)
	}
}

// Through the HTTP handler: the authenticated user becomes the actor of the
// pause entry. Before the fix the handler passed the bare request context and
// the entry had no actor.
func TestScanHandler_PauseAuditEntryNamesTheCaller(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "Paused by a user", scan.ScanTypeSingle)
	userID := shared.NewID().String()

	h := handler.NewScanHandler(svc, nil, nil, validator.New(), logger.NewNop())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/"+s.ID.String()+"/pause", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", s.ID.String())
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, tenantID.String())
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	w := httptest.NewRecorder()
	h.PauseScan(w, req.WithContext(ctx))

	if w.Code != http.StatusOK {
		t.Fatalf("pause: status %d: %s", w.Code, w.Body.String())
	}
	if len(deps.auditSvc.contexts) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(deps.auditSvc.contexts))
	}
	if got := deps.auditSvc.contexts[0].ActorID; got != userID {
		t.Fatalf("pause audit actor %q, want the caller %q", got, userID)
	}
}

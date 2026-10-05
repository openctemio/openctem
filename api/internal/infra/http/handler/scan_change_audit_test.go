package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Only the methods these paths call; anything else panics on the nil embed.
type auditProfileRepo struct {
	scanprofile.Repository
	byID map[shared.ID]*scanprofile.ScanProfile
}

func (r *auditProfileRepo) Create(_ context.Context, p *scanprofile.ScanProfile) error {
	r.byID[p.ID] = p
	return nil
}

func (r *auditProfileRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*scanprofile.ScanProfile, error) {
	if p, ok := r.byID[id]; ok {
		return p, nil
	}
	return nil, shared.ErrNotFound
}

func (r *auditProfileRepo) Delete(_ context.Context, _ shared.ID, id shared.ID) error {
	delete(r.byID, id)
	return nil
}

type auditCommandRepo struct {
	commanddom.Repository
	cmd *commanddom.Command
}

func (r *auditCommandRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*commanddom.Command, error) {
	return r.cmd, nil
}

func (r *auditCommandRepo) Delete(_ context.Context, _, _ shared.ID) error { return nil }

func auditedRequest(method, target string, body []byte, tenantID, userID, id string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	if id != "" {
		rctx.URLParams.Add("id", id)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	return req.WithContext(ctx)
}

func requireAuditEntry(t *testing.T, logs []*auditdom.AuditLog, action auditdom.Action, rt auditdom.ResourceType, resourceID, userID string) {
	t.Helper()
	for _, l := range logs {
		if l.Action() != action {
			continue
		}
		if l.ResourceType() != rt || l.ResourceID() != resourceID {
			t.Fatalf("%s: resource %s/%s, want %s/%s", action, l.ResourceType(), l.ResourceID(), rt, resourceID)
		}
		if l.ActorID() == nil || l.ActorID().String() != userID {
			t.Fatalf("%s: actor %v, want %s", action, l.ActorID(), userID)
		}
		return
	}
	t.Fatalf("no %s audit entry (got %d entries)", action, len(logs))
}

// Scan profiles were changed with no audit entry at all: the service has no
// audit dependency and the handler wrote none.
func TestScanProfileChangesAreAudited(t *testing.T) {
	tenantID, userID := shared.NewID(), shared.NewID().String()
	repo := &auditProfileRepo{byID: map[shared.ID]*scanprofile.ScanProfile{}}
	auditRepo := &fakeAuditRepo{}
	h := NewScanProfileHandler(scan.NewScanProfileService(repo, logger.NewNop()), validator.New(), logger.NewNop())
	h.SetAuditService(auditapp.NewAuditService(auditRepo, logger.NewNop()))

	w := httptest.NewRecorder()
	h.Create(w, auditedRequest(http.MethodPost, "/api/v1/scan-profiles",
		[]byte(`{"name":"Nightly deep"}`), tenantID.String(), userID, ""))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d: %s", w.Code, w.Body.String())
	}
	var created *scanprofile.ScanProfile
	for _, p := range repo.byID {
		created = p
	}
	requireAuditEntry(t, auditRepo.logs, auditdom.ActionScanProfileCreated, auditdom.ResourceTypeScanProfile, created.ID.String(), userID)

	w = httptest.NewRecorder()
	h.Delete(w, auditedRequest(http.MethodDelete, "/api/v1/scan-profiles/"+created.ID.String(), nil,
		tenantID.String(), userID, created.ID.String()))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d: %s", w.Code, w.Body.String())
	}
	requireAuditEntry(t, auditRepo.logs, auditdom.ActionScanProfileDeleted, auditdom.ResourceTypeScanProfile, created.ID.String(), userID)
}

// A user deleting a sensor command left no trace either.
func TestCommandDeleteIsAudited(t *testing.T) {
	tenantID, userID := shared.NewID(), shared.NewID().String()
	cmd, err := commanddom.NewCommand(tenantID, commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	auditRepo := &fakeAuditRepo{}
	h := NewCommandHandler(command.NewService(&auditCommandRepo{cmd: cmd}, logger.NewNop()), validator.New(), logger.NewNop())
	h.SetAuditService(auditapp.NewAuditService(auditRepo, logger.NewNop()))

	w := httptest.NewRecorder()
	h.Delete(w, auditedRequest(http.MethodDelete, "/api/v1/commands/"+cmd.ID.String(), nil,
		tenantID.String(), userID, cmd.ID.String()))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d: %s", w.Code, w.Body.String())
	}
	requireAuditEntry(t, auditRepo.logs, auditdom.ActionCommandDeleted, auditdom.ResourceTypeCommand, cmd.ID.String(), userID)
}

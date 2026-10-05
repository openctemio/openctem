package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// invScopeRepo is a minimal tenant repository that serves one invitation and
// records invitation deletions, so a handler test can prove which tenant the
// handler acted on.
type invScopeRepo struct {
	tenantdom.Repository
	inv        *tenantdom.Invitation
	deletedInv []shared.ID
}

func (r *invScopeRepo) GetInvitationByID(_ context.Context, tenantID, id shared.ID) (*tenantdom.Invitation, error) {
	if r.inv != nil && r.inv.ID() == id && r.inv.TenantID() == tenantID {
		return r.inv, nil
	}
	return nil, shared.ErrNotFound
}

func (r *invScopeRepo) DeleteInvitation(_ context.Context, tenantID, id shared.ID) error {
	if r.inv == nil || r.inv.ID() != id || r.inv.TenantID() != tenantID {
		return shared.ErrNotFound
	}
	r.deletedInv = append(r.deletedInv, id)
	return nil
}

// ctxWith sets the URL-path tenant (TeamIDKey, what RequireTeamAdmin authorized)
// and, separately, the JWT-claim tenant (TenantIDKey) so the two can diverge —
// exactly the confused-deputy setup: an attacker who is admin of the path
// tenant but holds a token scoped to a different tenant.
func ctxWith(pathTenant shared.ID, jwtTenant string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, middleware.TeamIDKey, pathTenant)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, jwtTenant)
	ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
	return ctx
}

func newInvScopeHandler(repo *invScopeRepo) *TenantHandler {
	svc := app.NewTenantService(repo, logger.NewNop())
	return NewTenantHandler(svc, validator.New(), logger.NewNop())
}

func deleteInvReq(h *TenantHandler, ctx context.Context, invID string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodDelete, "/", nil).WithContext(ctx)
	r.SetPathValue("invitationId", invID)
	w := httptest.NewRecorder()
	h.DeleteInvitation(w, r)
	return w
}

// TestDeleteInvitation_UsesPathTenantNotJWT is the regression test for the
// confused-deputy IDOR: DeleteInvitation must act on the URL-path tenant (the
// one RequireTeamAdmin checked), never the JWT-claim tenant.
func TestDeleteInvitation_UsesPathTenantNotJWT(t *testing.T) {
	orgA := shared.NewID() // the invitation's real owner / the attacker's JWT tenant
	orgB := shared.NewID() // the path tenant the attacker administers
	inviter := shared.NewID()
	inv, err := tenantdom.NewInvitation(orgA, "victim@a.test", tenantdom.RoleMember, inviter, []string{"00000000-0000-0000-0000-000000000003"})
	if err != nil {
		t.Fatal(err)
	}

	// Attack: path tenant = B (admin there), JWT tenant = A (the invitation's org).
	repo := &invScopeRepo{inv: inv}
	h := newInvScopeHandler(repo)
	w := deleteInvReq(h, ctxWith(orgB, orgA.String()), inv.ID().String())
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete must be refused with 404, got %d (deleted=%v)", w.Code, repo.deletedInv)
	}
	if len(repo.deletedInv) != 0 {
		t.Fatalf("cross-tenant delete must not touch the other tenant's invitation: deleted=%v", repo.deletedInv)
	}

	// Legitimate: path tenant = A matches the invitation's owner → deletes.
	repo2 := &invScopeRepo{inv: inv}
	h2 := newInvScopeHandler(repo2)
	w2 := deleteInvReq(h2, ctxWith(orgA, orgA.String()), inv.ID().String())
	if w2.Code != http.StatusNoContent {
		t.Fatalf("legitimate same-tenant delete should succeed (204), got %d", w2.Code)
	}
	if len(repo2.deletedInv) != 1 || repo2.deletedInv[0] != inv.ID() {
		t.Fatalf("legitimate delete should remove the invitation, deleted=%v", repo2.deletedInv)
	}
}

// TestResendInvitation_UsesPathTenantNotJWT: the same confused-deputy guard on
// the resend path. The cross-tenant attempt must be refused with 404 before any
// email work.
func TestResendInvitation_UsesPathTenantNotJWT(t *testing.T) {
	orgA := shared.NewID()
	orgB := shared.NewID()
	inviter := shared.NewID()
	inv, err := tenantdom.NewInvitation(orgA, "victim@a.test", tenantdom.RoleMember, inviter, []string{"00000000-0000-0000-0000-000000000003"})
	if err != nil {
		t.Fatal(err)
	}

	repo := &invScopeRepo{inv: inv}
	h := newInvScopeHandler(repo)
	r := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctxWith(orgB, orgA.String()))
	r.SetPathValue("invitationId", inv.ID().String())
	w := httptest.NewRecorder()
	h.ResendInvitation(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant resend must be refused with 404, got %d", w.Code)
	}
}

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// linkRepo serves one invitation by id and by token hash, and keeps what
// UpdateInvitation was asked to store.
type linkRepo struct {
	tenantdom.Repository
	inv     *tenantdom.Invitation
	updated *tenantdom.Invitation
	// What UpdateInvitation was asked to write, read at call time (the service
	// puts the raw token back on its in-memory entity afterwards).
	storedToken   string
	storedExpires time.Time
	deleted       []shared.ID
}

func (r *linkRepo) GetInvitationByID(_ context.Context, tenantID, id shared.ID) (*tenantdom.Invitation, error) {
	if r.inv != nil && r.inv.ID() == id && r.inv.TenantID() == tenantID {
		return r.inv, nil
	}
	return nil, shared.ErrNotFound
}

func (r *linkRepo) GetInvitationByToken(_ context.Context, tokenHash string) (*tenantdom.Invitation, error) {
	if r.inv != nil && r.inv.Token() == tokenHash {
		return r.inv, nil
	}
	return nil, shared.ErrNotFound
}

func (r *linkRepo) UpdateInvitation(_ context.Context, inv *tenantdom.Invitation) error {
	r.updated, r.storedToken, r.storedExpires = inv, inv.Token(), inv.ExpiresAt()
	return nil
}

func (r *linkRepo) DeleteInvitation(_ context.Context, _, id shared.ID) error {
	r.deleted = append(r.deleted, id)
	return nil
}

type denyStepUp struct{}

func (denyStepUp) RequireRecentAuth(context.Context, string) error {
	return errors.New("recent authentication required")
}

// invitationWithToken is an invitation as the database holds it: the token is
// the hash of rawToken.
func invitationWithToken(t *testing.T, org shared.ID, rawToken string, expiresAt time.Time, accepted bool, privileged bool) *tenantdom.Invitation {
	t.Helper()
	var at *time.Time
	if accepted {
		now := time.Now()
		at = &now
	}
	inv := tenantdom.ReconstituteInvitation(shared.NewID(), org, "invitee@a.test", tenantdom.RoleMember, nil,
		crypto.HashToken(rawToken), shared.NewID(), expiresAt, at, time.Now().Add(-48*time.Hour))
	if privileged {
		if err := inv.SetInviteeInfo(tenantdom.InviteeInfo{Kind: tenantdom.MemberKindExternal, Privileged: true}); err != nil {
			t.Fatal(err)
		}
	}
	return inv
}

func linkHandler(repo *linkRepo, gate shared.RecentAuthGate) *TenantHandler {
	svc := tenant.NewTenantService(repo, logger.NewNop())
	if gate != nil {
		svc.SetStepUpGate(gate)
	}
	return NewTenantHandler(svc, validator.New(), logger.NewNop())
}

func callLink(h *TenantHandler, handle func(http.ResponseWriter, *http.Request), pathTenant shared.ID, invID string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctxWith(pathTenant, pathTenant.String()))
	r.SetPathValue("invitationId", invID)
	w := httptest.NewRecorder()
	handle(w, r)
	return w
}

func TestRegenerateInvitationLink(t *testing.T) {
	org := shared.NewID()
	future := time.Now().Add(72 * time.Hour)

	t.Run("rotates the token: new one shown once, hash stored, old one dead, expiry unchanged", func(t *testing.T) {
		inv := invitationWithToken(t, org, "old-raw-token", future, false, false)
		repo := &linkRepo{inv: inv}
		h := linkHandler(repo, nil)
		w := callLink(h, h.RegenerateInvitationLink, org, inv.ID().String())
		if w.Code != http.StatusOK {
			t.Fatalf("status %d %s", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control = %q, a bearer link must not be cached", w.Header().Get("Cache-Control"))
		}
		var resp InvitationLinkResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Token == "" {
			t.Fatalf("body %s", w.Body.String())
		}
		if resp.Token == "old-raw-token" {
			t.Fatal("the token was not rotated")
		}
		if repo.updated == nil || repo.storedToken == resp.Token || repo.storedToken != crypto.HashToken(resp.Token) {
			t.Fatal("the raw token was stored instead of its hash")
		}
		if !repo.storedExpires.Equal(future) {
			t.Fatalf("expiry changed to %v", repo.storedExpires)
		}
		// The old link no longer resolves: the lookup is by the new hash.
		if repo.storedToken == crypto.HashToken("old-raw-token") {
			t.Fatal("the old token still matches")
		}
	})

	t.Run("another organization's invitation is a 404 and nothing is stored", func(t *testing.T) {
		inv := invitationWithToken(t, org, "tok", future, false, false)
		repo := &linkRepo{inv: inv}
		h := linkHandler(repo, nil)
		w := callLink(h, h.RegenerateInvitationLink, shared.NewID(), inv.ID().String())
		if w.Code != http.StatusNotFound || repo.updated != nil {
			t.Fatalf("cross-tenant: %d, updated=%v", w.Code, repo.updated != nil)
		}
	})

	t.Run("a privileged invitation needs a recent re-authentication", func(t *testing.T) {
		inv := invitationWithToken(t, org, "tok", future, false, true)
		repo := &linkRepo{inv: inv}
		h := linkHandler(repo, denyStepUp{})
		w := callLink(h, h.RegenerateInvitationLink, org, inv.ID().String())
		if w.Code == http.StatusOK || repo.updated != nil {
			t.Fatalf("privileged without step-up: %d, updated=%v", w.Code, repo.updated != nil)
		}
		// An ordinary invitation does not.
		plain := invitationWithToken(t, org, "tok2", future, false, false)
		repo2 := &linkRepo{inv: plain}
		h2 := linkHandler(repo2, denyStepUp{})
		if w := callLink(h2, h2.RegenerateInvitationLink, org, plain.ID().String()); w.Code != http.StatusOK {
			t.Fatalf("ordinary invitation: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("accepted and expired invitations are refused", func(t *testing.T) {
		for name, inv := range map[string]*tenantdom.Invitation{
			"accepted": invitationWithToken(t, org, "tok", future, true, false),
			"expired":  invitationWithToken(t, org, "tok", time.Now().Add(-time.Hour), false, false),
		} {
			repo := &linkRepo{inv: inv}
			h := linkHandler(repo, nil)
			if w := callLink(h, h.RegenerateInvitationLink, org, inv.ID().String()); w.Code != http.StatusBadRequest || repo.updated != nil {
				t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
			}
		}
	})
}

func TestRenewInvitation(t *testing.T) {
	org := shared.NewID()

	t.Run("an expired invitation gets a new lifetime and a new token", func(t *testing.T) {
		inv := invitationWithToken(t, org, "old", time.Now().Add(-time.Hour), false, false)
		repo := &linkRepo{inv: inv}
		h := linkHandler(repo, nil)
		w := callLink(h, h.RenewInvitation, org, inv.ID().String())
		if w.Code != http.StatusOK {
			t.Fatalf("status %d %s", w.Code, w.Body.String())
		}
		var resp InvitationLinkResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Token == "" || repo.updated == nil || repo.storedToken != crypto.HashToken(resp.Token) {
			t.Fatalf("token not rotated and hashed: %s", w.Body.String())
		}
		if got := time.Until(repo.storedExpires); got < 6*24*time.Hour || got > 7*24*time.Hour+time.Minute {
			t.Fatalf("new lifetime %v, want about 7 days", got)
		}
		if !resp.Invitation.Pending {
			t.Fatal("the renewed invitation is not pending")
		}
	})

	t.Run("a pending invitation is refused (copy its link instead)", func(t *testing.T) {
		inv := invitationWithToken(t, org, "tok", time.Now().Add(time.Hour), false, false)
		repo := &linkRepo{inv: inv}
		h := linkHandler(repo, nil)
		if w := callLink(h, h.RenewInvitation, org, inv.ID().String()); w.Code != http.StatusBadRequest || repo.updated != nil {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
}

func declineReq(h *TenantHandler, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"token":"`+token+`"}`))
	w := httptest.NewRecorder()
	h.DeclineInvitationToken(w, r)
	return w
}

// The public decline deletes (revokes) a pending invitation only: an accepted
// one is a membership now, and an expired one is not declined.
func TestDeclineInvitationOnlyWhenPending(t *testing.T) {
	org := shared.NewID()
	raw := strings.Repeat("a", 43)

	pending := invitationWithToken(t, org, raw, time.Now().Add(time.Hour), false, false)
	repo := &linkRepo{inv: pending}
	if w := declineReq(linkHandler(repo, nil), raw); w.Code != http.StatusNoContent || len(repo.deleted) != 1 {
		t.Fatalf("pending: %d %s deleted=%v", w.Code, w.Body.String(), repo.deleted)
	}

	for name, inv := range map[string]*tenantdom.Invitation{
		"accepted": invitationWithToken(t, org, raw, time.Now().Add(time.Hour), true, false),
		"expired":  invitationWithToken(t, org, raw, time.Now().Add(-time.Hour), false, false),
	} {
		repo := &linkRepo{inv: inv}
		w := declineReq(linkHandler(repo, nil), raw)
		if w.Code != http.StatusConflict || len(repo.deleted) != 0 {
			t.Fatalf("%s: %d %s deleted=%v", name, w.Code, w.Body.String(), repo.deleted)
		}
	}
}

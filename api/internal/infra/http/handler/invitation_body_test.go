package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// The invitation token moved from the URL path into the request body
// (RFC-041 §3.2 P4): POST /api/v1/invitations/{lookup,accept,decline}. These
// tests pin the body routes and that the deprecated path routes share their
// behavior.

const (
	invTokenA = "tokA-0123456789abcdefghijklmnopqrstuvwxyzABCD" // 45 chars
	invTokenB = "tokB-0123456789abcdefghijklmnopqrstuvwxyzABCD"
)

// invBodyRepo serves invitations by hashed token (as the real store does) and
// records what the service changed.
type invBodyRepo struct {
	tenantdom.Repository
	tenants     map[shared.ID]*tenantdom.Tenant
	byHash      map[string]*tenantdom.Invitation
	tokenCalls  int
	deleted     []shared.ID
	memberships []*tenantdom.Membership
}

func (r *invBodyRepo) GetInvitationByToken(_ context.Context, hash string) (*tenantdom.Invitation, error) {
	r.tokenCalls++
	if inv, ok := r.byHash[hash]; ok {
		return inv, nil
	}
	return nil, shared.ErrNotFound
}

func (r *invBodyRepo) GetByID(_ context.Context, id shared.ID) (*tenantdom.Tenant, error) {
	if t, ok := r.tenants[id]; ok {
		return t, nil
	}
	return nil, shared.ErrNotFound
}

func (r *invBodyRepo) GetInvitationByID(_ context.Context, tenantID, id shared.ID) (*tenantdom.Invitation, error) {
	for _, inv := range r.byHash {
		if inv.ID() == id && inv.TenantID() == tenantID {
			return inv, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r *invBodyRepo) DeleteInvitation(_ context.Context, _ shared.ID, id shared.ID) error {
	r.deleted = append(r.deleted, id)
	return nil
}

func (r *invBodyRepo) GetMembership(context.Context, shared.ID, shared.ID) (*tenantdom.Membership, error) {
	return nil, shared.ErrNotFound
}

func (r *invBodyRepo) AcceptInvitationTx(_ context.Context, _ *tenantdom.Invitation, m *tenantdom.Membership) error {
	r.memberships = append(r.memberships, m)
	return nil
}

// twoOrgs builds organizations A and B, each with one pending invitation:
// invTokenA invites alice@a.test to A, invTokenB invites bob@b.test to B.
func twoOrgs(t *testing.T) (*invBodyRepo, *tenantdom.Invitation, *tenantdom.Invitation) {
	t.Helper()
	repo := &invBodyRepo{tenants: map[shared.ID]*tenantdom.Tenant{}, byHash: map[string]*tenantdom.Invitation{}}
	mk := func(name, slug, email, token string) *tenantdom.Invitation {
		tn, err := tenantdom.NewTenant(name, slug, shared.NewID().String())
		if err != nil {
			t.Fatal(err)
		}
		repo.tenants[tn.ID()] = tn
		inv, err := tenantdom.NewInvitation(tn.ID(), email, tenantdom.RoleMember, shared.NewID(),
			[]string{"00000000-0000-0000-0000-000000000003"})
		if err != nil {
			t.Fatal(err)
		}
		repo.byHash[crypto.HashToken(token)] = inv
		return inv
	}
	return repo, mk("Org A", "org-a", "alice@a.test", invTokenA), mk("Org B", "org-b", "bob@b.test", invTokenB)
}

func newInvBodyHandler(repo *invBodyRepo) *TenantHandler {
	return NewTenantHandler(tenant.NewTenantService(repo, logger.NewNop()), validator.New(), logger.NewNop())
}

func postJSON(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
}

func tokenBody(tok string) string {
	b, _ := json.Marshal(InvitationTokenRequest{Token: tok})
	return string(b)
}

func withUser(t *testing.T, r *http.Request, email string) *http.Request {
	t.Helper()
	u, err := userdom.NewProvisionedLocalUser(email, "User")
	if err != nil {
		t.Fatal(err)
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.LocalUserKey, u))
}

func TestLookupInvitation_TokenInBody(t *testing.T) {
	repo, invA, _ := twoOrgs(t)
	h := newInvBodyHandler(repo)

	w := httptest.NewRecorder()
	h.LookupInvitation(w, postJSON(tokenBody(invTokenA)))
	if w.Code != http.StatusOK {
		t.Fatalf("lookup = %d, want 200: %s", w.Code, w.Body)
	}
	var got InvitationLookupResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// The token resolves to its own invitation and organization, never another's.
	if got.Invitation.ID != invA.ID().String() || got.Invitation.Email != "alice@a.test" ||
		got.Tenant.ID != invA.TenantID().String() || got.Tenant.Slug != "org-a" || !got.Invitation.Pending {
		t.Fatalf("lookup returned the wrong invitation: %+v", got)
	}
	if strings.Contains(w.Body.String(), invTokenA) || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("lookup response must not echo the token: %s", w.Body)
	}
}

func TestLookupInvitation_RefusesBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"no body":        "",
		"not json":       "token=" + invTokenA,
		"missing token":  `{}`,
		"short token":    tokenBody("short"),
		"long token":     tokenBody(strings.Repeat("a", 101)),
		"NUL in token":   tokenBody(strings.Repeat("a", 44) + "\x00"),
		"oversized body": `{"token":"` + strings.Repeat("a", maxInvitationTokenBody) + `"}`,
	} {
		repo, _, _ := twoOrgs(t)
		w := httptest.NewRecorder()
		newInvBodyHandler(repo).LookupInvitation(w, postJSON(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, w.Code)
		}
		if repo.tokenCalls != 0 {
			t.Errorf("%s: a malformed token reached the store", name)
		}
	}
}

func TestLookupInvitation_UnknownToken404(t *testing.T) {
	repo, _, _ := twoOrgs(t)
	w := httptest.NewRecorder()
	newInvBodyHandler(repo).LookupInvitation(w, postJSON(tokenBody("tokC-0123456789abcdefghijklmnopqrstuvwxyzABCD")))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown token = %d, want 404", w.Code)
	}
}

// Declining with A's token deletes A's invitation and nothing in B.
func TestDeclineInvitationToken_OnlyItsOwnInvitation(t *testing.T) {
	repo, invA, _ := twoOrgs(t)
	w := httptest.NewRecorder()
	newInvBodyHandler(repo).DeclineInvitationToken(w, postJSON(tokenBody(invTokenA)))
	if w.Code != http.StatusNoContent {
		t.Fatalf("decline = %d, want 204: %s", w.Code, w.Body)
	}
	if len(repo.deleted) != 1 || repo.deleted[0] != invA.ID() {
		t.Fatalf("decline deleted %v, want only %s", repo.deleted, invA.ID())
	}
}

func TestAcceptInvitationToken(t *testing.T) {
	t.Run("needs a signed-in user", func(t *testing.T) {
		repo, _, _ := twoOrgs(t)
		w := httptest.NewRecorder()
		newInvBodyHandler(repo).AcceptInvitationToken(w, postJSON(tokenBody(invTokenA)))
		if w.Code != http.StatusUnauthorized || len(repo.memberships) != 0 {
			t.Fatalf("anonymous accept = %d (memberships %d), want 401 and none", w.Code, len(repo.memberships))
		}
	})
	t.Run("another account cannot use the token", func(t *testing.T) {
		repo, _, _ := twoOrgs(t)
		w := httptest.NewRecorder()
		// bob (invited to B) presents A's token: he must not join A.
		newInvBodyHandler(repo).AcceptInvitationToken(w, withUser(t, postJSON(tokenBody(invTokenA)), "bob@b.test"))
		if w.Code != http.StatusBadRequest || len(repo.memberships) != 0 {
			t.Fatalf("foreign accept = %d (memberships %d), want 400 and none", w.Code, len(repo.memberships))
		}
	})
	t.Run("the invited email joins the invitation's organization", func(t *testing.T) {
		repo, invA, _ := twoOrgs(t)
		w := httptest.NewRecorder()
		newInvBodyHandler(repo).AcceptInvitationToken(w, withUser(t, postJSON(tokenBody(invTokenA)), "Alice@A.test"))
		if w.Code != http.StatusOK {
			t.Fatalf("accept = %d, want 200: %s", w.Code, w.Body)
		}
		if len(repo.memberships) != 1 || repo.memberships[0].TenantID() != invA.TenantID() {
			t.Fatalf("membership not created in the invitation's organization: %v", repo.memberships)
		}
	})
}

// The deprecated path routes run the same code as the body routes.
func TestInvitationPathAliases_SameBehaviour(t *testing.T) {
	repo, invA, _ := twoOrgs(t)
	h := newInvBodyHandler(repo)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetPathValue("token", invTokenA)
	w := httptest.NewRecorder()
	h.GetInvitationPreview(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), invA.ID().String()) {
		t.Fatalf("preview alias = %d: %s", w.Code, w.Body)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetPathValue("token", "short")
	w = httptest.NewRecorder()
	h.AcceptInvitation(w, withUser(t, r, "alice@a.test"))
	if w.Code != http.StatusBadRequest || repo.tokenCalls != 1 {
		t.Fatalf("a malformed path token = %d (store calls %d), want 400 before the store", w.Code, repo.tokenCalls)
	}
}

func TestAcceptInvitationWithRefreshBody_RefusesBadToken(t *testing.T) {
	h := &LocalAuthHandler{logger: logger.NewNop()}
	for _, body := range []string{"", "{}", `{"token":"short"}`, `{"token":` + `"` + strings.Repeat("a", 101) + `"}`} {
		w := httptest.NewRecorder()
		h.AcceptInvitationWithRefreshBody(w, postJSON(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q: got %d, want 400", body, w.Code)
		}
	}
}

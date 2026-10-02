package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"

	scimapp "github.com/openctemio/api/internal/app/scim"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/scimtoken"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
)

// --- fakes implementing the exported scim interfaces ---

type scimUserStore struct {
	byEmail map[string]*userdom.User
	byID    map[shared.ID]*userdom.User
}

func (f *scimUserStore) GetByEmail(_ context.Context, email string) (*userdom.User, error) {
	if u, ok := f.byEmail[email]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}
func (f *scimUserStore) GetByID(_ context.Context, id shared.ID) (*userdom.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}
func (f *scimUserStore) Create(_ context.Context, u *userdom.User) error {
	f.byEmail[u.Email()] = u
	f.byID[u.ID()] = u
	return nil
}
func (f *scimUserStore) Update(_ context.Context, u *userdom.User) error {
	f.byEmail[u.Email()] = u
	f.byID[u.ID()] = u
	return nil
}

type scimMemberStore struct {
	byUser map[shared.ID]*tenantdom.Membership
}

func (m *scimMemberStore) GetMembership(_ context.Context, userID, _ shared.ID) (*tenantdom.Membership, error) {
	if mem, ok := m.byUser[userID]; ok {
		return mem, nil
	}
	return nil, shared.ErrNotFound
}
func (m *scimMemberStore) ListMembersByTenant(_ context.Context, _ shared.ID) ([]*tenantdom.Membership, error) {
	out := make([]*tenantdom.Membership, 0, len(m.byUser))
	for _, mem := range m.byUser {
		out = append(out, mem)
	}
	return out, nil
}
func (m *scimMemberStore) AddMember(_ context.Context, tenantID, userID shared.ID, role string) error {
	mem, err := tenantdom.NewMembership(userID, tenantID, tenantdom.Role(role), nil)
	if err != nil {
		return err
	}
	m.byUser[userID] = mem
	return nil
}
func (m *scimMemberStore) findMembership(id shared.ID) *tenantdom.Membership {
	for _, mem := range m.byUser {
		if mem.ID() == id {
			return mem
		}
	}
	return nil
}
func (m *scimMemberStore) SuspendMember(_ context.Context, _, membershipID shared.ID) error {
	if mem := m.findMembership(membershipID); mem != nil {
		return mem.Suspend(shared.NewID())
	}
	return shared.ErrNotFound
}
func (m *scimMemberStore) ReactivateMember(_ context.Context, _, membershipID shared.ID) error {
	if mem := m.findMembership(membershipID); mem != nil {
		return mem.Reactivate()
	}
	return shared.ErrNotFound
}

type stubSCIMAuth struct {
	tenantID shared.ID
}

func (s stubSCIMAuth) Authenticate(_ context.Context, plaintext string) (*scimtoken.ScimToken, error) {
	if plaintext == "" {
		return nil, scimtoken.ErrNotFound
	}
	return scimtoken.New(shared.NewID(), s.tenantID, "t", "hash", "pref"), nil
}

type scimTestEnv struct {
	handler  *SCIMHandler
	auth     func(http.Handler) http.Handler
	tenantID shared.ID
	users    *scimUserStore
	members  *scimMemberStore
}

func newSCIMTestEnv() *scimTestEnv {
	users := &scimUserStore{byEmail: map[string]*userdom.User{}, byID: map[shared.ID]*userdom.User{}}
	members := &scimMemberStore{byUser: map[shared.ID]*tenantdom.Membership{}}
	prov := scimapp.NewProvisioningService(users, members, members, logger.NewNop())
	tenantID := shared.NewID()
	return &scimTestEnv{
		handler:  NewSCIMHandler(prov, logger.NewNop()),
		auth:     middleware.SCIMAuth(stubSCIMAuth{tenantID: tenantID}),
		tenantID: tenantID,
		users:    users,
		members:  members,
	}
}

// serve runs a request through SCIMAuth → the given handler, with a Bearer token
// (unless withoutToken) and an optional {id} chi path param.
func (e *scimTestEnv) serve(t *testing.T, h http.HandlerFunc, method, target string, body []byte, id string, withoutToken bool) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if !withoutToken {
		r.Header.Set("Authorization", "Bearer oct_scim_test")
	}
	if id != "" {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	}
	w := httptest.NewRecorder()
	e.auth(h).ServeHTTP(w, r)
	return w
}

func (e *scimTestEnv) seedMember(t *testing.T, email string) shared.ID {
	t.Helper()
	u, err := userdom.New(email, "Seed")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_ = e.users.Create(context.Background(), u)
	if err := e.members.AddMember(context.Background(), e.tenantID, u.ID(), "member"); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	return u.ID()
}

func TestSCIM_CreateUser_201(t *testing.T) {
	e := newSCIMTestEnv()
	body, _ := json.Marshal(map[string]any{"userName": "new@example.com", "active": true})
	w := e.serve(t, e.handler.CreateUser, http.MethodPost, "/scim/v2/Users", body, "", false)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["active"] != true {
		t.Errorf("active = %v, want true", resp["active"])
	}
	if resp["userName"] != "new@example.com" {
		t.Errorf("userName = %v", resp["userName"])
	}
}

func TestSCIM_CreateUser_NoAuth_401(t *testing.T) {
	e := newSCIMTestEnv()
	body, _ := json.Marshal(map[string]any{"userName": "x@example.com"})
	w := e.serve(t, e.handler.CreateUser, http.MethodPost, "/scim/v2/Users", body, "", true)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestSCIM_GetUser(t *testing.T) {
	e := newSCIMTestEnv()
	uid := e.seedMember(t, "get@example.com")
	w := e.serve(t, e.handler.GetUser, http.MethodGet, "/scim/v2/Users/"+uid.String(), nil, uid.String(), false)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestSCIM_GetUser_NotMember_404(t *testing.T) {
	e := newSCIMTestEnv()
	other := shared.NewID()
	w := e.serve(t, e.handler.GetUser, http.MethodGet, "/scim/v2/Users/"+other.String(), nil, other.String(), false)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestSCIM_ListUsers_Filter(t *testing.T) {
	e := newSCIMTestEnv()
	e.seedMember(t, "a@example.com")
	e.seedMember(t, "b@example.com")
	q := url.Values{"filter": {`userName eq "a@example.com"`}}.Encode()
	w := e.serve(t, e.handler.ListUsers, http.MethodGet, "/scim/v2/Users?"+q, nil, "", false)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		TotalResults int              `json:"totalResults"`
		Resources    []map[string]any `json:"Resources"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.TotalResults != 1 || len(resp.Resources) != 1 {
		t.Fatalf("filter should match 1, got total=%d res=%d", resp.TotalResults, len(resp.Resources))
	}
}

func TestSCIM_PatchUser_Deactivate(t *testing.T) {
	e := newSCIMTestEnv()
	uid := e.seedMember(t, "patch@example.com")
	body, _ := json.Marshal(map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	})
	w := e.serve(t, e.handler.PatchUser, http.MethodPatch, "/scim/v2/Users/"+uid.String(), body, uid.String(), false)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !e.members.byUser[uid].IsSuspended() {
		t.Error("membership should be suspended after PATCH active:false")
	}
}

func TestSCIM_DeleteUser_Deactivates(t *testing.T) {
	e := newSCIMTestEnv()
	uid := e.seedMember(t, "del@example.com")
	w := e.serve(t, e.handler.DeleteUser, http.MethodDelete, "/scim/v2/Users/"+uid.String(), nil, uid.String(), false)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if !e.members.byUser[uid].IsSuspended() {
		t.Error("DELETE should suspend (deprovision) the membership")
	}
}

func TestSCIM_PatchUser_UnsupportedPath_400(t *testing.T) {
	e := newSCIMTestEnv()
	uid := e.seedMember(t, "p2@example.com")
	body, _ := json.Marshal(map[string]any{
		"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "x"}},
	})
	w := e.serve(t, e.handler.PatchUser, http.MethodPatch, "/scim/v2/Users/"+uid.String(), body, uid.String(), false)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unsupported patch path", w.Code)
	}
}

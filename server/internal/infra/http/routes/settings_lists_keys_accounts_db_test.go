package routes

// API keys list (derived expired state, owner name, owner filter) and service
// accounts list (roles, teams, AI-agent mark) against a migrated database.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/accesscontrol"
	"github.com/openctemio/openctem/server/internal/app/apikey"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

func (h *grbHarness) apiKey(tenant, owner shared.ID, name, status string, expiresIn time.Duration) string {
	h.t.Helper()
	id := shared.NewID()
	var exp any
	if expiresIn != 0 {
		exp = time.Now().Add(expiresIn)
	}
	h.exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id.String(), tenant.String(), owner.String(), name, "hash-"+id.String(), "oc_"+id.String()[:6], status, exp)
	return id.String()
}

// newServiceAccount creates an account; the tenant's removal removes it.
func (h *grbHarness) newServiceAccount(tenant shared.ID, name string) shared.ID {
	h.t.Helper()
	repo := postgres.NewServiceAccountRepository(&postgres.DB{DB: h.db})
	a := &serviceaccount.ServiceAccount{ID: shared.NewID(), TenantID: tenant, Name: name}
	if err := repo.Create(context.Background(), a); err != nil {
		h.t.Fatalf("service account: %v", err)
	}
	return a.ID
}

type keyRow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	OwnerName string `json:"owner_name"`
	OwnerKind string `json:"owner_kind"`
}

func TestAPIKeysList_ExpiredOwnerAndFilter_DB(t *testing.T) {
	h := newGRBHarness(t)
	log := logger.NewNop()
	sa := h.newServiceAccount(h.tenant, "Reporting bridge")
	h.exec(`UPDATE users SET name = 'Ada Admin' WHERE id = $1`, h.admin.String())

	h.apiKey(h.tenant, h.admin, "live", "active", 24*time.Hour)
	h.apiKey(h.tenant, h.admin, "never-expires", "active", 0)
	h.apiKey(h.tenant, h.admin, "lapsed", "active", -time.Hour)
	h.apiKey(h.tenant, h.admin, "stored-expired", "expired", -time.Hour)
	h.apiKey(h.tenant, h.admin, "revoked", "revoked", 24*time.Hour)
	h.apiKey(h.tenant, sa, "bridge-key", "active", 24*time.Hour)
	h.apiKey(h.tenant, h.member, "member-key", "active", 24*time.Hour)
	// Another organization's key and account.
	otherUser := h.user(h.other, "internal", "")
	h.apiKey(h.other, otherUser, "foreign-key", "active", -time.Hour)
	foreignSA := h.newServiceAccount(h.other, "Foreign bridge")
	h.apiKey(h.other, foreignSA, "foreign-bridge-key", "active", 24*time.Hour)

	svc := apikey.NewService(postgres.NewAPIKeyRepository(&postgres.DB{DB: h.db}), "test-pepper", log)
	hd := handler.NewAPIKeyHandler(svc, validator.New(), log)

	list := func(tenant shared.ID, userID string, admin bool, q string) (int, []keyRow) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/api-keys?"+q, nil)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
		ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
		rec := httptest.NewRecorder()
		hd.List(rec, req.WithContext(ctx))
		var body struct {
			Data []keyRow `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Data
	}
	names := func(rows []keyRow) string {
		var n []string
		for _, r := range rows {
			n = append(n, r.Name)
		}
		return strings.Join(n, ",")
	}
	byName := func(rows []keyRow, name string) keyRow {
		for _, r := range rows {
			if r.Name == name {
				return r
			}
		}
		t.Fatalf("key %q not listed in %s", name, names(rows))
		return keyRow{}
	}

	code, all := list(h.tenant, h.admin.String(), true, "per_page=50")
	if code != 200 || len(all) != 7 {
		t.Fatalf("admin list = %d %s", code, names(all))
	}
	if st := byName(all, "lapsed").Status; st != "expired" {
		t.Errorf("a key past its expiry reads %q, want expired", st)
	}
	var stored string
	_ = h.db.QueryRowContext(context.Background(), `SELECT status FROM api_keys WHERE name = 'lapsed'`).Scan(&stored)
	if stored != "active" {
		t.Errorf("the row was rewritten to %q; the state must be derived at read time", stored)
	}
	for name, want := range map[string]string{"live": "active", "never-expires": "active", "stored-expired": "expired", "revoked": "revoked"} {
		if st := byName(all, name).Status; st != want {
			t.Errorf("%s status = %q, want %q", name, st, want)
		}
	}
	if r := byName(all, "live"); r.OwnerName != "Ada Admin" || r.OwnerKind != "person" {
		t.Errorf("owner = %q/%q", r.OwnerName, r.OwnerKind)
	}
	if r := byName(all, "bridge-key"); r.OwnerName != "Reporting bridge" || r.OwnerKind != "service" {
		t.Errorf("service owner = %q/%q", r.OwnerName, r.OwnerKind)
	}

	// Status filters follow the derived state.
	if _, rows := list(h.tenant, h.admin.String(), true, "status=active&per_page=50"); strings.Contains(names(rows), "lapsed") || strings.Contains(names(rows), "stored-expired") || !strings.Contains(names(rows), "live") {
		t.Errorf("status=active = %s", names(rows))
	}
	if _, rows := list(h.tenant, h.admin.String(), true, "status=expired&per_page=50"); len(rows) != 2 || !strings.Contains(names(rows), "lapsed") || !strings.Contains(names(rows), "stored-expired") {
		t.Errorf("status=expired = %s", names(rows))
	}

	// Owner filter: service accounts of this organization only; me.
	if _, rows := list(h.tenant, h.admin.String(), true, "owner=service_accounts"); names(rows) != "bridge-key" {
		t.Errorf("owner=service_accounts = %s", names(rows))
	}
	if _, rows := list(h.tenant, h.admin.String(), true, "owner=me&per_page=50"); len(rows) != 5 || strings.Contains(names(rows), "bridge-key") || strings.Contains(names(rows), "member-key") {
		t.Errorf("owner=me = %s", names(rows))
	}
	if code, _ := list(h.tenant, h.admin.String(), true, "owner=everyone"); code != http.StatusBadRequest {
		t.Errorf("owner=everyone = %d, want 400", code)
	}

	// A member sees only their own keys, whatever the filter says.
	if _, rows := list(h.tenant, h.member.String(), false, "per_page=50"); names(rows) != "member-key" {
		t.Errorf("member list = %s", names(rows))
	}
	if _, rows := list(h.tenant, h.member.String(), false, "owner=service_accounts"); len(rows) != 0 {
		t.Errorf("member with owner=service_accounts = %s", names(rows))
	}

	// Another organization sees none of this one's keys or owners.
	if _, rows := list(h.other, otherUser.String(), true, "per_page=50"); len(rows) != 2 || strings.Contains(","+names(rows)+",", ",live,") || strings.Contains(","+names(rows)+",", ",bridge-key,") {
		t.Errorf("another organization's list = %s", names(rows))
	}
	if _, rows := list(h.other, otherUser.String(), true, "owner=service_accounts"); names(rows) != "foreign-bridge-key" {
		t.Errorf("another organization's service keys = %s", names(rows))
	}
}

func TestServiceAccountsList_RolesTeamsAIAgent_DB(t *testing.T) {
	h := newGRBHarness(t)
	log := logger.NewNop()
	tid := h.tenant.String()

	plain := h.newServiceAccount(h.tenant, "Plain")
	bridge := h.newServiceAccount(h.tenant, "Bridge")
	aiAcct := h.newServiceAccount(h.tenant, "Triage agent")
	foreign := h.newServiceAccount(h.other, "Foreign")

	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, bridge.String(), tid, h.analyst.String())
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, h.team.String(), bridge.String())
	// An ended membership does not count.
	second := h.newTeam(h.tenant)
	h.exec(`INSERT INTO group_members (group_id, user_id, role, expires_at) VALUES ($1, $2, 'member', now() - interval '1 day')`, second.String(), bridge.String())
	h.exec(`INSERT INTO ai_agents (user_id, tenant_id, attest_due_at) VALUES ($1, $2, now() + interval '30 days')`, aiAcct.String(), tid)
	h.apiKey(h.tenant, bridge, "live", "active", 24*time.Hour)
	h.apiKey(h.tenant, bridge, "lapsed", "active", -time.Hour)

	repo := postgres.NewServiceAccountRepository(&postgres.DB{DB: h.db})
	hd := handler.NewServiceAccountHandler(accesscontrol.NewServiceAccountService(repo, nil, log), nil, validator.New(), log)

	list := func(tenant string) []map[string]any {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/service-accounts", nil)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
		rec := httptest.NewRecorder()
		hd.List(rec, req.WithContext(ctx))
		if rec.Code != http.StatusOK {
			t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Data []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Data
	}
	find := func(rows []map[string]any, id shared.ID) map[string]any {
		for _, r := range rows {
			if r["id"] == id.String() {
				return r
			}
		}
		t.Fatalf("account %s not listed", id)
		return nil
	}
	refs := func(v any) []string {
		var out []string
		for _, x := range v.([]any) {
			out = append(out, x.(map[string]any)["name"].(string))
		}
		return out
	}

	rows := list(tid)
	if len(rows) != 3 {
		t.Fatalf("listed %d accounts, want 3 (no foreign one)", len(rows))
	}
	b := find(rows, bridge)
	if got := refs(b["roles"]); len(got) != 1 || got[0] != "analyst" {
		t.Errorf("bridge roles = %v", got)
	}
	if got := refs(b["teams"]); len(got) != 1 {
		t.Errorf("bridge teams = %v, want only the active membership", got)
	}
	if b["api_keys"].(float64) != 1 {
		t.Errorf("bridge api_keys = %v, want 1 (the lapsed key is not active)", b["api_keys"])
	}
	if b["ai_agent"] != false || find(rows, aiAcct)["ai_agent"] != true {
		t.Errorf("ai_agent marks wrong: bridge=%v acct=%v", b["ai_agent"], find(rows, aiAcct)["ai_agent"])
	}
	p := find(rows, plain)
	if p["roles"] == nil || p["teams"] == nil {
		t.Fatal("roles and teams must be [] not null")
	}
	if len(refs(p["roles"])) != 0 || len(refs(p["teams"])) != 0 {
		t.Errorf("plain account has roles/teams: %v %v", p["roles"], p["teams"])
	}

	// Another organization sees only its own account, with none of ours.
	other := list(h.other.String())
	if len(other) != 1 || other[0]["id"] != foreign.String() {
		t.Fatalf("another organization's list = %v", other)
	}
	if len(refs(other[0]["roles"])) != 0 || len(refs(other[0]["teams"])) != 0 {
		t.Errorf("foreign account shows memberships: %v", other[0])
	}
}

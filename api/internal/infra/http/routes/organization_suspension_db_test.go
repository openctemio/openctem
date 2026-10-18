package routes

// Organization suspension and account block over the real route
// registration and a migrated database: a session token and an API key of
// a suspended organization are refused from the next request on, and work
// again the request after the suspension is lifted; a blocked account's
// session and key are refused too. The MCP token path asks the same
// membership checker as API keys, exercised here against the database
// (docs/architecture/organization-suspension.md).

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/app/suspension"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jwt"
)

func TestOrganizationSuspension_Routes_DB(t *testing.T) {
	var gate *suspension.Gate
	h := newKeyRESTHarness(t, func(hs *Handlers) {
		// The harness opened the database already; the gate reads the same one.
		gate = suspension.NewGate(postgres.NewOrganizationStatusRepository(&postgres.DB{DB: mustOpenTestDB(t)}), nil, nil)
		hs.OrganizationGate = gate
	})
	t.Cleanup(func() { organizationAccessMiddleware, organizationGate = nil, nil })
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	store := postgres.NewOrganizationStatusRepository(db)

	tenantID := h.tenant(`{}`)
	other := h.tenant(`{}`)
	userID := h.member(tenantID, "member")
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, userID, other)
	key, _ := h.mint(tenantID, userID, 0, "assets:read")
	session := func(tid string) map[string]string {
		tok, err := h.gen.GenerateTenantScopedAccessToken(userID, "m@it.test", "Member", uuid.NewString(),
			jwt.TenantMembership{TenantID: tid, Role: "member"}, false, 0, "password")
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"Authorization": "Bearer " + tok.AccessToken}
	}
	probe := func(headers map[string]string) (int, string) {
		return h.do(keyReq{method: http.MethodGet, path: "/api/v1/key-probe", headers: headers})
	}
	keyHeaders := map[string]string{"Authorization": "Bearer " + key}
	tid, _ := shared.IDFromString(tenantID)
	uid, _ := shared.IDFromString(userID)
	checker := apikey.NewMembershipChecker(postgres.NewTenantRepository(db), postgres.NewUserRepository(db), gate)

	if code, body := probe(session(tenantID)); code != http.StatusOK {
		t.Fatalf("session before suspension: %d %s", code, body)
	}
	if code, _ := probe(keyHeaders); code != http.StatusOK {
		t.Fatalf("key before suspension: %d", code)
	}

	if ok, err := store.Suspend(ctx, tid, nil, "abuse", time.Now()); err != nil || !ok {
		t.Fatalf("suspend: %v %v", ok, err)
	}

	t.Run("session and API key of the suspended organization are refused", func(t *testing.T) {
		for name, hd := range map[string]map[string]string{"session": session(tenantID), "api key": keyHeaders} {
			code, body := probe(hd)
			if code != http.StatusForbidden || !strings.Contains(body, tenantdom.CodeOrganizationSuspended) ||
				!strings.Contains(body, tenantdom.MessageOrganizationSuspended) || strings.Contains(body, "abuse") {
				t.Errorf("%s: %d %s, want 403 %s without the reason", name, code, body, tenantdom.CodeOrganizationSuspended)
			}
		}
	})

	t.Run("the same member's other organization keeps working", func(t *testing.T) {
		if code, body := probe(session(other)); code != http.StatusOK {
			t.Errorf("other organization: %d %s", code, body)
		}
	})

	t.Run("MCP and API key membership check refuses the suspended organization", func(t *testing.T) {
		ok, err := checker.IsActiveMember(ctx, tid, uid)
		if err != nil || ok {
			t.Errorf("IsActiveMember(suspended) = %v %v, want false", ok, err)
		}
		otherID, _ := shared.IDFromString(other)
		if ok, err := checker.IsActiveMember(ctx, otherID, uid); err != nil || !ok {
			t.Errorf("IsActiveMember(other) = %v %v, want true", ok, err)
		}
	})

	if ok, err := store.Unsuspend(ctx, tid); err != nil || !ok {
		t.Fatalf("unsuspend: %v %v", ok, err)
	}

	t.Run("lifting restores access on the next request", func(t *testing.T) {
		if code, body := probe(session(tenantID)); code != http.StatusOK {
			t.Errorf("session after lift: %d %s", code, body)
		}
		if code, _ := probe(keyHeaders); code != http.StatusOK {
			t.Errorf("key after lift: %d", code)
		}
	})

	t.Run("a blocked account's session, key and MCP check are refused", func(t *testing.T) {
		dir := postgres.NewPlatformUserDirectory(db)
		if ok, err := dir.SetBlocked(ctx, uid, true, nil, "spam"); err != nil || !ok {
			t.Fatalf("block: %v %v", ok, err)
		}
		for name, hd := range map[string]map[string]string{"session": session(tenantID), "api key": keyHeaders} {
			if code, _ := probe(hd); code != http.StatusUnauthorized {
				t.Errorf("%s of a blocked account: %d, want 401", name, code)
			}
		}
		if ok, err := checker.IsActiveMember(ctx, tid, uid); err != nil || ok {
			t.Errorf("IsActiveMember(blocked) = %v %v, want false", ok, err)
		}
		if ok, err := dir.SetBlocked(ctx, uid, false, nil, "resolved"); err != nil || !ok {
			t.Fatalf("unblock: %v %v", ok, err)
		}
		if code, _ := probe(session(tenantID)); code != http.StatusOK {
			t.Errorf("session after unblock: %d", code)
		}
	})
}

// mustOpenTestDB opens DATABASE_URL (the harness skips when it is unset).
func mustOpenTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", testdb.URL())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

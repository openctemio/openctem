package routes

// Refusals on the routes that take a sensitive action (step-up actions), over
// the real registration and a migrated database: a member, an administrator
// of another organization, an `oct_` API key of the owner and an owner whose
// session has not re-authenticated are all refused; an administrator of the
// organization inside the step-up window succeeds.

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// switchableStepUp answers "authenticated just now" or "an hour ago".
type switchableStepUp struct{ fresh *bool }

func (s switchableStepUp) RecentAuthAt(context.Context, string, string) (time.Time, error) {
	if *s.fresh {
		return time.Now(), nil
	}
	return time.Now().Add(-time.Hour), nil
}

// sensitiveHarness is the API-key REST harness with the handlers the
// sensitive routes need and a step-up checker the test switches.
type sensitiveHarness struct {
	*keyRESTHarness
	fresh *bool
}

func newSensitiveHarness(t *testing.T) *sensitiveHarness {
	t.Helper()
	fresh := true
	h := newKeyRESTHarness(t, func(hs *Handlers) {
		// The harness has checked DATABASE_URL before it calls this.
		sqldb, err := sql.Open("postgres", testdb.URL())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sqldb.Close() })
		db := &postgres.DB{DB: sqldb}
		log := logger.NewNop()
		tenantSvc := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log)
		tenantSvc.SetLifecycleRepository(postgres.NewMemberLifecycleRepository(db))
		hs.Tenant = handler.NewTenantHandler(tenantSvc, validator.New(), log)
		hs.StepUp = switchableStepUp{fresh: &fresh}
	})
	return &sensitiveHarness{keyRESTHarness: h, fresh: &fresh}
}

// session mints a user session token for userID in tenantID.
func (h *sensitiveHarness) session(tenantID, userID, role string) string {
	h.t.Helper()
	isAdmin := role == "owner" || role == "admin"
	tok, err := h.gen.GenerateTenantScopedAccessTokenWithPermissions(userID, "akrest-"+userID[:8]+"@it.test", "IT", uuid.NewString(),
		jwt.TenantMembership{TenantID: tenantID, Role: role}, nil, isAdmin, 0, "password")
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.AccessToken
}

func (h *sensitiveHarness) call(method, path, bearer string) (int, string) {
	h.t.Helper()
	return h.do(keyReq{method: method, path: path, headers: map[string]string{"Authorization": "Bearer " + bearer}})
}

func (h *sensitiveHarness) membershipID(tenantID, userID string) string {
	h.t.Helper()
	var id string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT id FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func TestSensitiveActionRefusals_Offboard_DB(t *testing.T) {
	h := newSensitiveHarness(t)
	tid, other := h.tenant(`{}`), h.tenant(`{}`)
	owner, admin, member := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member")
	target := h.member(tid, "member")
	otherAdmin := h.member(other, "admin")
	path := "/api/v1/organization/members/" + h.membershipID(tid, target) + "/offboard"
	ownerKey, _ := h.mint(tid, owner, 0)

	status := func() string {
		var s string
		if err := h.db.QueryRow(`SELECT COALESCE(status,'active') FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, tid, target).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	for _, tc := range []struct {
		name, bearer string
		fresh        bool
		want         int
		code         string
	}{
		{"member", h.session(tid, member, "member"), true, http.StatusForbidden, ""},
		{"administrator of another organization", h.session(other, otherAdmin, "admin"), true, http.StatusNotFound, ""},
		{"API key of the owner (read-only)", ownerKey, true, http.StatusForbidden, ""},
		{"owner without a recent sign-in", h.session(tid, owner, "owner"), false, http.StatusForbidden, string(middleware.CodeStepUpRequired)},
		{"administrator without a recent sign-in", h.session(tid, admin, "admin"), false, http.StatusForbidden, string(middleware.CodeStepUpRequired)},
	} {
		*h.fresh = tc.fresh
		code, body := h.call(http.MethodPost, path, tc.bearer)
		if code != tc.want || (tc.code != "" && !strings.Contains(body, tc.code)) {
			t.Errorf("%s: got %d %s, want %d %s", tc.name, code, body, tc.want, tc.code)
		}
		if s := status(); s != "active" {
			t.Fatalf("%s: a refused offboarding changed the member to %q", tc.name, s)
		}
	}

	// The removed DELETE no longer reaches the offboarding.
	*h.fresh = false
	if code, _ := h.call(http.MethodDelete, "/api/v1/tenants/"+tid+"/members/"+h.membershipID(tid, target), h.session(tid, admin, "admin")); code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /tenants/{t}/members/{id}: got %d, want 405", code)
	}

	*h.fresh = true
	if code, body := h.call(http.MethodPost, path, h.session(tid, admin, "admin")); code != http.StatusOK {
		t.Fatalf("administrator inside the step-up window: got %d %s, want 200", code, body)
	}
	if s := status(); s != "offboarded" {
		t.Fatalf("member status after offboarding = %q, want offboarded", s)
	}
}

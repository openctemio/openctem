package routes

// Refusals on the routes that take a sensitive action (step-up actions), over
// the real registration and a migrated database: a member, an administrator
// of another organization, an `oct_` API key of the owner and an owner or
// administrator whose session has not re-authenticated are all refused; an
// administrator of the organization inside the step-up window succeeds.

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/integration"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/credential"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
	fresh   *bool
	pg      *postgres.DB
	secrets *credential.SecretProtector
	creds   *handler.CredentialImportHandler
}

func newSensitiveHarness(t *testing.T) *sensitiveHarness {
	t.Helper()
	fresh := true
	out := &sensitiveHarness{fresh: &fresh}
	h := newKeyRESTHarness(t, func(hs *Handlers) {
		// The harness has checked DATABASE_URL before it calls this.
		sqldb, err := sql.Open("postgres", testdb.URL())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sqldb.Close() })
		db := &postgres.DB{DB: sqldb}
		out.pg = db
		log := logger.NewNop()
		checker := switchableStepUp{fresh: &fresh}
		gate := middleware.RecentAuthGate{Checker: checker, Window: authapp.StepUpWindow}
		v := validator.New()

		tenantSvc := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log)
		tenantSvc.SetLifecycleRepository(postgres.NewMemberLifecycleRepository(db))
		hs.Tenant = handler.NewTenantHandler(tenantSvc, v, log)

		sensorSvc := sensorapp.NewSensorService(postgres.NewSensorRepository(db), nil, log)
		sensorSvc.SetIdentityPolicyRepository(postgres.NewSensorIdentityPolicyRepository(db))
		sensorSvc.SetStepUpGate(gate)
		hs.Sensor = handler.NewSensorHandler(sensorSvc, v, log)

		c, err := crypto.NewCipherFromHex(strings.Repeat("2e", 32))
		if err != nil {
			t.Fatal(err)
		}
		out.secrets = credential.NewSecretProtector(c, []byte("refusal-test"))
		credSvc := integration.NewCredentialImportService(postgres.NewExposureRepository(db), nil, log)
		credSvc.SetSecretProtector(out.secrets)
		out.creds = handler.NewCredentialImportHandler(credSvc, v, log)
		hs.CredentialImport = out.creds

		hs.StepUp = checker
	})
	out.keyRESTHarness = h
	out.creds.SetAuditService(h.audit) // reveal is refused unless audited
	return out
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

// call sends method path with body ("" sends {}) as bearer.
func (h *sensitiveHarness) call(method, path, body, bearer string) (int, string) {
	h.t.Helper()
	if body == "" {
		body = "{}"
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
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

// org is one organization with an owner, an administrator and a member, plus
// an administrator of another organization and the owner's API key.
type org struct {
	tid, other                       string
	owner, admin, member, otherAdmin string
	ownerKey                         string
}

func (h *sensitiveHarness) org() org {
	h.t.Helper()
	o := org{tid: h.tenant(`{}`), other: h.tenant(`{}`)}
	o.owner, o.admin, o.member = h.member(o.tid, "owner"), h.member(o.tid, "admin"), h.member(o.tid, "member")
	o.otherAdmin = h.member(o.other, "admin")
	o.ownerKey, _ = h.mint(o.tid, o.owner, 0)
	for _, tid := range []string{o.tid, o.other} {
		id := tid
		h.t.Cleanup(func() { // before the harness removes the tenant
			_, _ = h.db.ExecContext(context.Background(), `DELETE FROM exposure_events WHERE tenant_id = $1`, id)
			_, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensors WHERE tenant_id = $1`, id)
		})
	}
	return o
}

// refusal is one caller that must be refused, and how.
type refusal struct {
	name, bearer string
	fresh        bool
	want         int
	code         string
}

const crossTenant = "administrator of another organization"

// refusals is the standard refusal table for an organization's sensitive
// route on one object: member, another organization's administrator (404:
// the object does not exist for them), the owner's API key, and the owner
// and administrator outside the window. For a route without an object (the
// tenant comes from the token) the cross-tenant case does not apply: pass
// withoutCrossTenant.
func (h *sensitiveHarness) refusals(o org, withoutCrossTenant bool) []refusal {
	rs := []refusal{
		{"member", h.session(o.tid, o.member, "member"), true, http.StatusForbidden, ""},
		{crossTenant, h.session(o.other, o.otherAdmin, "admin"), true, http.StatusNotFound, ""},
		{"API key of the owner (read-only)", o.ownerKey, true, http.StatusForbidden, ""},
		{"owner without a recent sign-in", h.session(o.tid, o.owner, "owner"), false, http.StatusForbidden, string(middleware.CodeStepUpRequired)},
		{"administrator without a recent sign-in", h.session(o.tid, o.admin, "admin"), false, http.StatusForbidden, string(middleware.CodeStepUpRequired)},
	}
	if withoutCrossTenant {
		rs = append(rs[:1], rs[2:]...)
	}
	return rs
}

// expectRefused runs every refusal against method path body and calls
// unchanged after each, which fails the test if the refused call had an
// effect.
func (h *sensitiveHarness) expectRefused(rs []refusal, method, path, body string, unchanged func(who string)) {
	h.t.Helper()
	for _, tc := range rs {
		*h.fresh = tc.fresh
		code, resp := h.call(method, path, body, tc.bearer)
		if code != tc.want || (tc.code != "" && !strings.Contains(resp, tc.code)) {
			h.t.Errorf("%s %s as %s: got %d %s, want %d %s", method, path, tc.name, code, resp, tc.want, tc.code)
		}
		unchanged(tc.name)
	}
	*h.fresh = true
}

func (h *sensitiveHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestSensitiveActionRefusals_Offboard_DB(t *testing.T) {
	h := newSensitiveHarness(t)
	o := h.org()
	target := h.member(o.tid, "member")
	path := "/api/v1/organization/members/" + h.membershipID(o.tid, target) + "/offboard"

	status := func() string {
		var s string
		if err := h.db.QueryRow(`SELECT COALESCE(status,'active') FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, o.tid, target).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	h.expectRefused(h.refusals(o, false), http.MethodPost, path, "", func(who string) {
		if s := status(); s != "active" {
			t.Fatalf("%s: a refused offboarding changed the member to %q", who, s)
		}
	})

	// The removed DELETE no longer reaches the offboarding.
	*h.fresh = false
	if code, _ := h.call(http.MethodDelete, "/api/v1/tenants/"+o.tid+"/members/"+h.membershipID(o.tid, target), "", h.session(o.tid, o.admin, "admin")); code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /tenants/{t}/members/{id}: got %d, want 405", code)
	}
	*h.fresh = true

	if code, body := h.call(http.MethodPost, path, "", h.session(o.tid, o.admin, "admin")); code != http.StatusOK {
		t.Fatalf("administrator inside the step-up window: got %d %s, want 200", code, body)
	}
	if s := status(); s != "offboarded" {
		t.Fatalf("member status after offboarding = %q, want offboarded", s)
	}
}

func TestSensitiveActionRefusals_SensorKeys_DB(t *testing.T) {
	h := newSensitiveHarness(t)
	o := h.org()
	h.exec(`UPDATE tenants SET sensor_bearer_keys_allowed = TRUE WHERE id = $1`, o.tid)
	sid := uuid.NewString()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix)
	        VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'standalone', $4, 'octs_tst')`,
		sid, o.tid, "refusal-"+sid[:8], "hash-"+sid)
	keyHash := func() string {
		var s string
		if err := h.db.QueryRow(`SELECT api_key_hash FROM sensors WHERE id = $1`, sid).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	sensors := func() int { return h.count(`SELECT count(*) FROM sensors WHERE tenant_id = $1`, o.tid) }

	// Creating a sensor: the organization comes from the token, so there is
	// no cross-tenant object.
	create := `{"name":"refusal-new","type":"worker"}`
	h.expectRefused(h.refusals(o, true), http.MethodPost, "/api/v1/sensors", create, func(who string) {
		if n := sensors(); n != 1 {
			t.Fatalf("%s: a refused create left %d sensors", who, n)
		}
	})

	// Regenerating a key: another organization's administrator gets 404.
	path := "/api/v1/sensors/" + sid + "/regenerate-key"
	h.expectRefused(h.refusals(o, false), http.MethodPost, path, "", func(who string) {
		if got := keyHash(); got != "hash-"+sid {
			t.Fatalf("%s: a refused regenerate changed the key", who)
		}
	})

	admin := h.session(o.tid, o.admin, "admin")
	if code, body := h.call(http.MethodPost, "/api/v1/sensors", create, admin); code != http.StatusCreated || !strings.Contains(body, "octs_") {
		t.Fatalf("administrator inside the window creates: got %d %s", code, body)
	}
	if code, body := h.call(http.MethodPost, path, "", admin); code != http.StatusOK || !strings.Contains(body, "octs_") {
		t.Fatalf("administrator inside the window regenerates: got %d %s", code, body)
	}
	if keyHash() == "hash-"+sid {
		t.Fatal("regenerate inside the window did not change the key")
	}
}

func TestSensitiveActionRefusals_IdentityPolicyWidening_DB(t *testing.T) {
	h := newSensitiveHarness(t)
	o := h.org()
	h.exec(`UPDATE tenants SET sensor_bearer_keys_allowed = FALSE WHERE id = $1`, o.tid)
	allowed := func() bool {
		var b bool
		if err := h.db.QueryRow(`SELECT sensor_bearer_keys_allowed FROM tenants WHERE id = $1`, o.tid).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	const widen, narrow = `{"bearer_keys_allowed":true}`, `{"bearer_keys_allowed":false}`
	const path = "/api/v1/sensors/identity-policy"

	// A member cannot change the policy, the API key cannot write, and the
	// owner outside the window cannot widen. (The organization comes from
	// the token: no cross-tenant object.)
	for _, tc := range h.refusals(o, true)[:3] {
		*h.fresh = tc.fresh
		if code, body := h.call(http.MethodPut, path, widen, tc.bearer); code != tc.want || (tc.code != "" && !strings.Contains(body, tc.code)) {
			t.Errorf("widen as %s: got %d %s, want %d %s", tc.name, code, body, tc.want, tc.code)
		}
		if allowed() {
			t.Fatalf("widen as %s: the refused request allowed bearer keys", tc.name)
		}
	}
	// Narrowing (already narrow) and re-asserting stay one click.
	*h.fresh = false
	owner := h.session(o.tid, o.owner, "owner")
	if code, body := h.call(http.MethodPut, path, narrow, owner); code != http.StatusOK {
		t.Fatalf("narrow outside the window: got %d %s, want 200", code, body)
	}
	*h.fresh = true
	if code, body := h.call(http.MethodPut, path, widen, owner); code != http.StatusOK || !allowed() {
		t.Fatalf("owner inside the window widens: got %d %s", code, body)
	}
	// Already wide: re-sending the same value needs no step-up.
	*h.fresh = false
	if code, body := h.call(http.MethodPut, path, widen, owner); code != http.StatusOK {
		t.Fatalf("re-asserting the current policy: got %d %s, want 200", code, body)
	}
	if code, body := h.call(http.MethodPut, path, narrow, owner); code != http.StatusOK || allowed() {
		t.Fatalf("narrowing outside the window: got %d %s, want 200", code, body)
	}
}

func TestSensitiveActionRefusals_CredentialReveal_DB(t *testing.T) {
	h := newSensitiveHarness(t)
	o := h.org()
	const secret = "Refusal-Test-Leaked-Pa55!"
	details := map[string]any{"credential_type": "password", credential.DetailSecretValue: secret}
	if err := h.secrets.Seal(details); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tid := shared.MustIDFromString(o.tid)
	ev := exposure.Reconstitute(shared.NewID(), tid, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateActive,
		"alice@refusal.test", "", details, "fp-"+uuid.NewString()[:8], "data_breach", now, now, nil, nil, "", now, now)
	if err := postgres.NewExposureRepository(h.pg).Create(context.Background(), ev); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	path := "/api/v1/credentials/" + ev.ID().String() + "/reveal"
	reveals := func() int {
		return h.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2`, o.tid, ev.ID().String())
	}

	h.expectRefused(h.refusals(o, false), http.MethodPost, path, "", func(who string) {
		if n := reveals(); n != 0 {
			t.Fatalf("%s: a refused reveal was audited %d times (it reached the handler)", who, n)
		}
	})

	code, body := h.call(http.MethodPost, path, "", h.session(o.tid, o.admin, "admin"))
	if code != http.StatusOK || !strings.Contains(body, secret) {
		t.Fatalf("administrator inside the window reveals: got %d %s", code, body)
	}
	if n := reveals(); n != 1 {
		t.Fatalf("reveal audit events = %d, want 1", n)
	}
}

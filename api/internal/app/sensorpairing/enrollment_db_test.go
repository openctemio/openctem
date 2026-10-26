package sensorpairing_test

// Organization enrollment tokens end to end against a migrated database
// (docs/architecture/sensor-pairing.md, "Enrollment tokens"): only the keyed
// hash is stored; a sensor that starts with the token joins the token's
// tenant with its presets through the key-bound exchange; uses count
// distinct keys, atomically; expired, revoked, exhausted, out-of-range and
// orphaned tokens are refused with one answer; another tenant can neither
// see, revoke nor approve anything of it.

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// enrollmentFixture wires the token store and makes actor an active member
// (the token's creator must stay one).
func enrollmentFixture(t *testing.T) (*fixture, sensorpairing.Actor) {
	f := newFixture(t)
	f.svc.SetEnrollmentTokens(postgres.NewSensorPairingRepository(&postgres.DB{DB: f.db}))
	a := f.org("org-enroll-" + shared.NewID().String()[:8])
	f.member(a)
	return f, a
}

func (f *fixture) member(a sensorpairing.Actor) {
	f.t.Helper()
	f.exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $2, 'admin', 'active')`,
		a.UserID.String(), a.TenantID.String())
	f.t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM tenant_members WHERE tenant_id = $1`, a.TenantID.String())
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM sensor_enrollment_tokens WHERE tenant_id = $1`, a.TenantID.String())
	})
}

func (f *fixture) createToken(a sensorpairing.Actor, in sensorpairing.CreateEnrollmentTokenInput) *sensorpairing.EnrollmentTokenView {
	f.t.Helper()
	if in.Name == "" {
		in.Name = "k8s-prod"
	}
	v, err := f.svc.CreateEnrollmentToken(context.Background(), a, in)
	if err != nil {
		f.t.Fatalf("create token: %v", err)
	}
	return v
}

func (f *fixture) enroll(s *sensor, token, ip string) error {
	resp, err := f.svc.Start(context.Background(), sensorpairing.StartInput{
		Request: pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(s.pub()),
			Commitment: pairing.Encode(s.commitment), EnrollmentToken: token,
			EnrollmentScope: pairing.EnrollmentScopeOrganization,
			Host:            pairing.HostFacts{Hostname: "node-" + s.thumb()[:6], OS: "linux", Arch: "amd64", SensorVersion: "0.25.0"}},
		PublicKey: s.pub(), SourceIP: net.ParseIP(ip),
	})
	if err != nil {
		return err
	}
	if s.platformPub, s.pNonce, err = pairing.VerifyStart(resp, s.pub(), s.commitment, "", sensorsig.Thumbprint); err != nil {
		f.t.Fatalf("platform signature: %v", err)
	}
	if resp.UserCode != "" {
		f.t.Fatalf("a token enrollment returned a user code")
	}
	s.resp = resp
	return nil
}

func (f *fixture) useCount(id string) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRowContext(context.Background(), `SELECT use_count FROM sensor_enrollment_tokens WHERE id = $1`, id).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestEnrollmentToken_EnrollsIntoTheTokensTenant_DB(t *testing.T) {
	f, a := enrollmentFixture(t)
	ctx := context.Background()
	v := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Labels: map[string]string{"env": "prod"}, MaxUses: 3})
	if _, ok := sensorkey.Valid(v.Token); !ok || !strings.HasPrefix(v.Token, sensorkey.PrefixEnrollmentToken) {
		t.Fatalf("token %q is not a checksummed octe_ token", v.Token)
	}
	if v.State != sensordom.EnrollmentTokenActive || v.MaxUses != 3 || v.TokenHint != v.Token[len(v.Token)-4:] {
		t.Fatalf("view: %+v", v)
	}
	var clear int
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_enrollment_tokens WHERE token_hash = $1`, v.Token).Scan(&clear)
	if clear != 0 {
		t.Fatal("the token is stored in clear")
	}
	// The list never carries the token.
	list, err := f.svc.ListEnrollmentTokens(ctx, a)
	if err != nil || len(list) != 1 || list[0].Token != "" {
		t.Fatalf("list: %+v %v", list, err)
	}

	s := newSensor(1)
	if err := f.enroll(s, v.Token, "203.0.113.30"); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	f.reveal(s)
	f.reveal(s) // a retried reveal is harmless
	st := f.status(s)
	if st.Status != pairing.StatusApproved || st.Identity == nil || st.Identity.TenantID != a.TenantID.String() || st.Identity.Scope != "" {
		t.Fatalf("after reveal: %+v", st)
	}
	if done, err := f.confirm(s, st.Identity); err != nil || done.Status != pairing.StatusCompleted {
		t.Fatalf("confirm: %+v %v", done, err)
	}
	var labels, trust string
	if err := f.db.QueryRowContext(ctx, `SELECT labels->>'env', COALESCE(trust_level, '') FROM sensors WHERE tenant_id = $1 AND id = $2`,
		a.TenantID.String(), st.Identity.SensorID).Scan(&labels, &trust); err != nil || labels != "prod" || trust != "new" {
		t.Fatalf("sensor labels %q trust %q: %v", labels, trust, err)
	}
	if n := f.useCount(v.ID); n != 1 {
		t.Fatalf("use_count = %d", n)
	}
}

func TestEnrollmentToken_UsesCountKeysAtomically_DB(t *testing.T) {
	f, a := enrollmentFixture(t)
	ctx := context.Background()
	v := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{MaxUses: 2, RequireApproval: true})

	first := newSensor(1)
	if err := f.enroll(first, v.Token, "203.0.113.31"); err != nil {
		t.Fatal(err)
	}
	// The same key asking again after its request expired spends nothing.
	f.exec(`UPDATE sensor_pairings SET status = 'expired' WHERE thumbprint = $1`, first.thumb())
	again := *first
	if err := f.enroll(&again, v.Token, "203.0.113.31"); err != nil {
		t.Fatalf("the same key again: %v", err)
	}
	if n := f.useCount(v.ID); n != 1 {
		t.Fatalf("use_count after the same key twice = %d", n)
	}
	if err := f.enroll(newSensor(2), v.Token, "203.0.113.32"); err != nil {
		t.Fatal(err)
	}
	if err := f.enroll(newSensor(3), v.Token, "203.0.113.33"); !errors.Is(err, sensorpairing.ErrEnrollmentRefused) {
		t.Fatalf("a third key on a two-use token: %v", err)
	}

	// Concurrent starts never spend more than the token has.
	race := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "race", MaxUses: 3})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := f.enroll(newSensor(byte(i)), race.Token, "203.0.113.40"); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok != 3 || f.useCount(race.ID) != 3 {
		t.Fatalf("%d starts succeeded, use_count %d; want 3", ok, f.useCount(race.ID))
	}
	_ = ctx
}

func TestEnrollmentToken_Refusals_DB(t *testing.T) {
	f, a := enrollmentFixture(t)
	ctx := context.Background()
	refused := func(name, token, ip string) {
		t.Helper()
		if err := f.enroll(newSensor(9), token, ip); !errors.Is(err, sensorpairing.ErrEnrollmentRefused) {
			t.Errorf("%s: %v, want the uniform refusal", name, err)
		}
	}
	refused("unknown", "octe_"+strings.Repeat("a", 49), "203.0.113.50")

	ranged := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "ranged", AllowedCIDRs: []string{"10.20.0.0/16"}})
	refused("outside the source ranges", ranged.Token, "203.0.113.50")
	if err := f.enroll(newSensor(1), ranged.Token, "10.20.3.4"); err != nil {
		t.Errorf("inside the source ranges: %v", err)
	}

	revoked := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "revoked"})
	rid, _ := shared.IDFromString(revoked.ID)
	if rv, err := f.svc.RevokeEnrollmentToken(ctx, a, rid); err != nil || rv.State != sensordom.EnrollmentTokenRevoked {
		t.Fatalf("revoke: %+v %v", rv, err)
	}
	refused("revoked", revoked.Token, "203.0.113.50")
	if _, err := f.svc.RevokeEnrollmentToken(ctx, a, rid); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Errorf("revoking twice: %v", err)
	}

	// Revoked after the sensor started, before it revealed: nothing is approved.
	late := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "revoked-late"})
	ls := newSensor(2)
	if err := f.enroll(ls, late.Token, "203.0.113.51"); err != nil {
		t.Fatalf("enroll before revoke: %v", err)
	}
	lid, _ := shared.IDFromString(late.ID)
	if _, err := f.svc.RevokeEnrollmentToken(ctx, a, lid); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	lpid, _ := shared.IDFromString(ls.resp.PairingID)
	if err := f.svc.Reveal(ctx, lpid, ls.thumb(), pairing.RevealRequest{SensorNonce: pairing.Encode(ls.nonce)}); !errors.Is(err, sensorpairing.ErrEnrollmentRefused) {
		t.Errorf("reveal after revoke: %v, want the uniform refusal", err)
	}
	if st := f.status(ls); st.Status == pairing.StatusApproved || st.Identity != nil {
		t.Errorf("a token revoked before the reveal approved the sensor: %+v", st)
	}

	expiring := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "expiring", TTL: time.Hour})
	f.now = f.now.Add(2 * time.Hour)
	refused("expired", expiring.Token, "203.0.113.50")
	f.now = time.Now()

	orphan := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "orphan"})
	f.exec(`UPDATE tenant_members SET status = 'suspended' WHERE tenant_id = $1`, a.TenantID.String())
	refused("creator no longer an active member", orphan.Token, "203.0.113.50")
	f.exec(`UPDATE tenant_members SET status = 'active' WHERE tenant_id = $1`, a.TenantID.String())
}

func TestEnrollmentToken_TenantIsolation_DB(t *testing.T) {
	f, a := enrollmentFixture(t)
	ctx := context.Background()
	b := f.org("org-enroll-other-" + shared.NewID().String()[:8])
	f.member(b)
	v := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{RequireApproval: true})
	tid, _ := shared.IDFromString(v.ID)

	if list, err := f.svc.ListEnrollmentTokens(ctx, b); err != nil || len(list) != 0 {
		t.Fatalf("another tenant lists the token: %+v %v", list, err)
	}
	if _, err := f.svc.RevokeEnrollmentToken(ctx, b, tid); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("another tenant revoked the token: %v", err)
	}

	s := newSensor(1)
	if err := f.enroll(s, v.Token, "203.0.113.60"); err != nil {
		t.Fatal(err)
	}
	f.reveal(s)
	// Require approval: the request waits, listed for its tenant only.
	if st := f.status(s); st.Status != pairing.StatusPending || st.Identity != nil {
		t.Fatalf("a require-approval token approved by itself: %+v", st)
	}
	pend, err := f.svc.ListPending(ctx, a)
	if err != nil || len(pend) != 1 || pend[0].SAS != s.sas() {
		t.Fatalf("pending for the token's tenant: %+v %v", pend, err)
	}
	if other, _ := f.svc.ListPending(ctx, b); len(other) != 0 {
		t.Fatalf("another tenant sees the pending request: %+v", other)
	}
	pid, _ := shared.IDFromString(s.resp.PairingID)
	if _, err := f.svc.Approve(ctx, b, pid, approve("")); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("another tenant approved the request: %v", err)
	}
	if _, err := f.svc.Approve(ctx, a, pid, approve("")); err != nil {
		t.Fatalf("the token's tenant approves: %v", err)
	}
	if st := f.status(s); st.Status != pairing.StatusApproved || st.Identity.TenantID != a.TenantID.String() {
		t.Fatalf("after approval: %+v", st)
	}
}

func TestEnrollmentToken_Validation_DB(t *testing.T) {
	f, a := enrollmentFixture(t)
	ctx := context.Background()
	b := f.org("org-enroll-zone-" + shared.NewID().String()[:8])
	zone := shared.NewID()
	f.exec(`INSERT INTO scan_zones (id, tenant_id, name, is_default) VALUES ($1, $2, 'b-zone', true)`, zone.String(), b.TenantID.String())
	t.Cleanup(func() { _, _ = f.db.ExecContext(ctx, `DELETE FROM scan_zones WHERE id = $1`, zone.String()) })

	for name, in := range map[string]sensorpairing.CreateEnrollmentTokenInput{
		"no name":                {Name: " "},
		"another tenant's zone":  {Name: "x", ZoneIDs: []shared.ID{zone}},
		"lifetime over 30 days":  {Name: "x", TTL: 31 * 24 * time.Hour},
		"lifetime under an hour": {Name: "x", TTL: time.Minute},
		"too many uses":          {Name: "x", MaxUses: 1001},
		"bad label":              {Name: "x", Labels: map[string]string{"Bad Key": "v"}},
		"bad range":              {Name: "x", AllowedCIDRs: []string{"not-a-cidr"}},
		"bad type":               {Name: "x", SensorType: "robot"},
	} {
		if _, err := f.svc.CreateEnrollmentToken(ctx, a, in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v, want a validation error", name, err)
		}
	}
	v := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "defaults"})
	if v.MaxUses != sensordom.DefaultEnrollmentTokenUses || v.ExpiresAt.Sub(v.CreatedAt) != sensordom.DefaultEnrollmentTokenTTL {
		t.Errorf("defaults: %+v", v)
	}
}

func TestEnrollmentToken_NeverUsedAsTheOtherKind_DB(t *testing.T) {
	f, a := enrollmentFixture(t)
	v := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "kinds"})
	// Sent as an instance token (a sensor configured for a shared sensor),
	// an organization token is refused and spends nothing.
	if err := f.startWithToken(newSensor(1), v.Token); !errors.Is(err, sensorpairing.ErrEnrollmentRefused) {
		t.Fatalf("an organization token used as an instance token: %v", err)
	}
	if n := f.useCount(v.ID); n != 0 {
		t.Fatalf("use_count = %d after a refused start", n)
	}
	// And an instance token is never an organization token.
	inst := f.issue(&auditSink{}, 0)
	if err := f.enroll(newSensor(2), inst, "203.0.113.70"); !errors.Is(err, sensorpairing.ErrEnrollmentRefused) {
		t.Fatalf("an instance token used as an organization token: %v", err)
	}
}

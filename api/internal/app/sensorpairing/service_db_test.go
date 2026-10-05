package sensorpairing_test

// Interactive pairing end to end against a migrated database
// (RFC-052 §4, threat model §6): a sensor and two organizations, every step
// and every refusal.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"net"
	"testing"
	"time"

	_ "github.com/lib/pq"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

const testSecret = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

type fakeStepUp struct{ ok bool }

func (f *fakeStepUp) VerifyStepUp(context.Context, string, string, authapp.StepUpProof) error {
	if f.ok {
		return nil
	}
	return authapp.ErrStepUpFailed
}

func (f *fakeStepUp) StepUpMethodFor(context.Context, string) (authapp.StepUpMethod, error) {
	return authapp.StepUpTOTP, nil
}

type fixture struct {
	t       *testing.T
	db      *sql.DB
	svc     *sensorpairing.Service
	sensors *sensorapp.SensorService
	stepUp  *fakeStepUp
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	sqldb, err := sql.Open("postgres", url)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.Ping(); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	db := &postgres.DB{DB: sqldb}
	sensorRepo := postgres.NewSensorRepository(db)
	sensors := sensorapp.NewSensorService(sensorRepo, nil, logger.NewNop())
	sensors.SetSigningKeyRepository(postgres.NewSensorSigningKeyRepository(db))
	svc, err := sensorpairing.NewService(postgres.NewSensorPairingRepository(db), sensorRepo, testSecret, "pepper-for-tests", logger.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, db: sqldb, svc: svc, sensors: sensors, stepUp: &fakeStepUp{ok: true}, now: time.Now()}
	svc.SetStepUp(f.stepUp)
	svc.SetEvents(sensors)
	svc.SetClock(func() time.Time { return f.now })
	return f
}

func (f *fixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(context.Background(), q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

// org creates a tenant and an admin user, and returns the actor.
func (f *fixture) org(name string) sensorpairing.Actor {
	f.t.Helper()
	tid, uid := shared.NewID(), shared.NewID()
	f.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, tid.String(), name, "pair-"+tid.String())
	f.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'pair admin')`, uid.String(), uid.String()+"@pair.test")
	f.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.db.ExecContext(ctx, `DELETE FROM sensor_pairings WHERE tenant_id = $1 OR approved_by = $2 OR denied_by = $2`, tid.String(), uid.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM sensors WHERE tenant_id = $1`, tid.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, uid.String())
	})
	return sensorpairing.Actor{TenantID: tid, UserID: uid, Email: "admin@" + name, IP: "198.51.100.7"}
}

// sensor is the sensor side of the protocol, as sdk-go runs it.
type sensor struct {
	key         ed25519.PrivateKey
	nonce       []byte
	commitment  []byte
	resp        *pairing.StartResponse
	platformPub ed25519.PublicKey
	pNonce      []byte
}

// newSensor makes a fresh key (seed only labels the call site): keys are
// unique for ever (sensor_keys.thumbprint), so tests never reuse one.
func newSensor(seed byte) *sensor {
	_ = seed
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	n := make([]byte, 32)
	_, _ = rand.Read(n)
	return &sensor{key: k, nonce: n, commitment: pairing.Commit(n)}
}

func (s *sensor) pub() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }
func (s *sensor) thumb() string          { return sensorsig.Thumbprint(s.pub()) }
func (s *sensor) sas() string {
	return pairing.ComputeSAS(s.pub(), s.platformPub, s.nonce, s.pNonce).String()
}

func (f *fixture) start(s *sensor, code, repair string) {
	f.t.Helper()
	resp, err := f.svc.Start(context.Background(), sensorpairing.StartInput{
		Request: pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(s.pub()),
			Commitment: pairing.Encode(s.commitment), Code: code, SensorID: repair,
			Host: pairing.HostFacts{Hostname: "scan01\u202e", OS: "linux", Arch: "amd64", SensorVersion: "0.10.0"}},
		PublicKey: s.pub(), SourceIP: net.ParseIP("203.0.113.9"),
	})
	if err != nil {
		f.t.Fatalf("start: %v", err)
	}
	// The sensor verifies the platform's signature (MITM: threat 3).
	if s.platformPub, s.pNonce, err = pairing.VerifyStart(resp, s.pub(), s.commitment, "", sensorsig.Thumbprint); err != nil {
		f.t.Fatalf("platform signature: %v", err)
	}
	s.resp = resp
}

func (f *fixture) reveal(s *sensor) {
	f.t.Helper()
	id, _ := shared.IDFromString(s.resp.PairingID)
	if err := f.svc.Reveal(context.Background(), id, s.thumb(), pairing.RevealRequest{SensorNonce: pairing.Encode(s.nonce)}); err != nil {
		f.t.Fatalf("reveal: %v", err)
	}
}

func (f *fixture) confirm(s *sensor, ident *pairing.Identity) (*pairing.StatusResponse, error) {
	id, _ := shared.IDFromString(s.resp.PairingID)
	sig := ed25519.Sign(s.key, pairing.ConfirmTranscript(s.resp.PairingID, ident.SensorID, ident.TenantID, s.thumb()))
	return f.svc.Confirm(context.Background(), id, s.thumb(), pairing.ConfirmRequest{SensorID: ident.SensorID, KeyID: s.thumb(), Signature: pairing.Encode(sig)})
}

func (f *fixture) status(s *sensor) *pairing.StatusResponse {
	f.t.Helper()
	id, _ := shared.IDFromString(s.resp.PairingID)
	st, err := f.svc.Status(context.Background(), id, s.thumb())
	if err != nil {
		f.t.Fatalf("status: %v", err)
	}
	return st
}

func approve(code string) sensorpairing.ApproveInput {
	return sensorpairing.ApproveInput{Code: code, FingerprintConfirmed: true, StepUp: authapp.StepUpProof{TOTP: "123456"}, Name: "dmz-01"}
}

func TestPairing_ForwardFlowAndRefusals_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.org("org-a"), f.org("org-b")
	s := newSensor(1)
	f.start(s, "", "")
	code := s.resp.UserCode
	if len(code) != 9 {
		t.Fatalf("user code %q", code)
	}
	id, _ := shared.IDFromString(s.resp.PairingID)

	// Not revealed yet: no SAS, so nothing to approve (uniform 404).
	if _, err := f.svc.Lookup(ctx, a, code); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("lookup before reveal: %v", err)
	}
	// A wrong nonce does not open the commitment.
	if err := f.svc.Reveal(ctx, id, s.thumb(), pairing.RevealRequest{SensorNonce: pairing.Encode(bytes.Repeat([]byte{9}, 32))}); err == nil {
		t.Fatal("a wrong nonce revealed")
	}
	f.reveal(s)

	v, err := f.svc.Lookup(ctx, a, code)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	// Both sides show the same fingerprint (threat 2/3).
	if v.SAS != s.sas() || v.KeyFingerprint != pairing.KeyFingerprint(s.thumb()) {
		t.Fatalf("SAS mismatch: platform %q sensor %q", v.SAS, s.sas())
	}
	if v.SourceIP != "203.0.113.9" || v.HostFacts.Hostname != "scan01" {
		t.Fatalf("host facts / source: %+v", v)
	}

	// Approval refusals: no fingerprint tick, failed step-up, no code,
	// wrong code.
	in := approve(code)
	in.FingerprintConfirmed = false
	if _, err := f.svc.Approve(ctx, a, id, in); !errors.Is(err, sensorpairing.ErrFingerprintRequired) {
		t.Fatalf("approve without fingerprint: %v", err)
	}
	f.stepUp.ok = false
	if _, err := f.svc.Approve(ctx, a, id, approve(code)); !errors.Is(err, authapp.ErrStepUpFailed) {
		t.Fatalf("approve with failed step-up: %v", err)
	}
	f.stepUp.ok = true
	if _, err := f.svc.Approve(ctx, a, id, approve("")); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("approve by id without the code: %v", err)
	}
	if _, err := f.svc.Approve(ctx, a, id, approve("AAAA-AAAA")); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("approve with a wrong code: %v", err)
	}
	// A stolen code without the key cannot poll (threat 9).
	other := newSensor(2)
	if _, err := f.svc.Status(ctx, id, other.thumb()); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("poll with another key: %v", err)
	}

	if _, err := f.svc.Approve(ctx, a, id, approve(code)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	st := f.status(s)
	if st.Status != pairing.StatusApproved || st.Identity == nil || st.Identity.TenantID != a.TenantID.String() {
		t.Fatalf("status after approve: %+v", st)
	}
	// The key is pending until the sensor confirms.
	if _, _, err := f.sensors.SigningIdentity(ctx, s.thumb(), true); err == nil {
		t.Fatal("a pending key authenticated")
	}
	// The code is spent: another organization (or the same) finds nothing
	// (threat 5).
	if _, err := f.svc.Lookup(ctx, b, code); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("lookup of a used code from another org: %v", err)
	}
	if _, err := f.svc.Approve(ctx, b, id, approve(code)); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("second approval: %v", err)
	}
	// A confirmation signed by another key is refused.
	bad := *s
	bad.key = other.key
	if _, err := f.confirm(&bad, st.Identity); err == nil {
		t.Fatal("confirm signed by another key")
	}
	if st, err = f.confirm(s, st.Identity); err != nil || st.Status != pairing.StatusCompleted {
		t.Fatalf("confirm: %v %+v", err, st)
	}
	ident, _, err := f.sensors.SigningIdentity(ctx, s.thumb(), true)
	if err != nil || ident.Sensor.TenantID == nil || *ident.Sensor.TenantID != a.TenantID || ident.Sensor.Name != "dmz-01" {
		t.Fatalf("active key: %v", err)
	}
	// Retried confirm is fine.
	if _, err := f.confirm(s, st.Identity); err != nil {
		t.Fatalf("retried confirm: %v", err)
	}
}

func TestPairing_Repair_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.org("org-a"), f.org("org-b")
	first := newSensor(11)
	f.start(first, "", "")
	f.reveal(first)
	id, _ := shared.IDFromString(first.resp.PairingID)
	if _, err := f.svc.Approve(ctx, a, id, approve(first.resp.UserCode)); err != nil {
		t.Fatal(err)
	}
	st := f.status(first)
	if _, err := f.confirm(first, st.Identity); err != nil {
		t.Fatal(err)
	}
	sensorID := st.Identity.SensorID

	// Re-pair with a new key.
	second := newSensor(12)
	f.start(second, "", sensorID)
	f.reveal(second)
	rid, _ := shared.IDFromString(second.resp.PairingID)
	// Another organization cannot see or claim it (cross-tenant: 404).
	if _, err := f.svc.Lookup(ctx, b, second.resp.UserCode); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("foreign re-pair lookup: %v", err)
	}
	if _, err := f.svc.Approve(ctx, b, rid, approve(second.resp.UserCode)); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("foreign re-pair approve: %v", err)
	}
	v, err := f.svc.Lookup(ctx, a, second.resp.UserCode)
	if err != nil || v.RepairSensorID != sensorID {
		t.Fatalf("re-pair lookup: %v %+v", err, v)
	}
	if _, err := f.svc.Approve(ctx, a, rid, approve(second.resp.UserCode)); err != nil {
		t.Fatalf("re-pair approve: %v", err)
	}
	// The old key stops at approval (a stolen key must not wait).
	if _, _, err := f.sensors.SigningIdentity(ctx, first.thumb(), true); err == nil {
		t.Fatal("the old key still authenticates after re-pair")
	}
	st2 := f.status(second)
	if st2.Identity == nil || st2.Identity.SensorID != sensorID || !st2.Identity.Repair {
		t.Fatalf("re-pair identity: %+v", st2.Identity)
	}
	if _, err := f.confirm(second, st2.Identity); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.sensors.SigningIdentity(ctx, second.thumb(), true); err != nil {
		t.Fatalf("new key: %v", err)
	}
	var revoked int
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_keys WHERE sensor_id = $1 AND status = 'revoked' AND revoked_reason = 'repaired'`, sensorID).Scan(&revoked)
	if revoked != 1 {
		t.Fatalf("history: %d revoked keys kept", revoked)
	}
}

func TestPairing_ReverseModeAndUniformAnswers_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.org("org-a"), f.org("org-b")
	exp, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{Name: "branch-office"})
	if err != nil || len(exp.Code) != 9 {
		t.Fatalf("expect: %v %+v", err, exp)
	}
	s := newSensor(21)
	f.start(s, exp.Code, "")
	if s.resp.UserCode != "" || s.resp.PairingID != exp.ID {
		t.Fatalf("reverse start answer: %+v", s.resp)
	}
	// A wrong code gets the same shape of answer (threat 5) and never
	// becomes approvable.
	decoy := newSensor(22)
	f.start(decoy, "ZZZZ-ZZZZ", "")
	if decoy.resp.UserCode != "" || decoy.resp.PairingID == "" {
		t.Fatalf("decoy answer differs: %+v", decoy.resp)
	}
	f.reveal(decoy)
	if f.status(decoy).Status != pairing.StatusPending {
		t.Fatal("decoy status")
	}

	f.reveal(s)
	eid, _ := shared.IDFromString(exp.ID)
	v, err := f.svc.GetExpectation(ctx, a, eid)
	if err != nil || v.SAS != s.sas() {
		t.Fatalf("expectation view: %v %+v", err, v)
	}
	if _, err := f.svc.GetExpectation(ctx, b, eid); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("another org read the expectation: %v", err)
	}
	if _, err := f.svc.Approve(ctx, b, eid, approve(exp.Code)); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("another org approved the expectation: %v", err)
	}
	in := approve("")
	in.Name = ""
	if _, err := f.svc.Approve(ctx, a, eid, in); err != nil {
		t.Fatalf("approve expectation: %v", err)
	}
	if st := f.status(s); st.Identity == nil || st.Identity.Name != "branch-office" {
		t.Fatalf("expectation name not used: %+v", st.Identity)
	}
}

func TestPairing_CapsDenyExpiry_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-a")

	// Deny.
	s := newSensor(31)
	f.start(s, "", "")
	f.reveal(s)
	id, _ := shared.IDFromString(s.resp.PairingID)
	if err := f.svc.Deny(ctx, a, id); err != nil {
		t.Fatal(err)
	}
	if st := f.status(s); st.Status != pairing.StatusDenied {
		t.Fatalf("denied status %q", st.Status)
	}
	if _, err := f.svc.Lookup(ctx, a, s.resp.UserCode); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatal("a denied code is found")
	}

	// Expiry.
	e := newSensor(32)
	f.start(e, "", "")
	f.reveal(e)
	f.now = f.now.Add(pairing.TTL + time.Second)
	if st := f.status(e); st.Status != pairing.StatusExpired {
		t.Fatalf("expired status %q", st.Status)
	}
	eid, _ := shared.IDFromString(e.resp.PairingID)
	if _, err := f.svc.Approve(ctx, a, eid, approve(e.resp.UserCode)); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("approve expired: %v", err)
	}
	f.now = time.Now()

	// Platform-wide open-request cap (threat 4).
	var open int
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_pairings WHERE status = 'pending' AND tenant_id IS NULL AND expires_at > NOW()`).Scan(&open)
	f.svc.SetMaxOpen(open)
	capped := newSensor(33)
	_, err := f.svc.Start(ctx, sensorpairing.StartInput{Request: pairing.StartRequest{Protocol: pairing.Version,
		PublicKey: pairing.Encode(capped.pub()), Commitment: pairing.Encode(capped.commitment)}, PublicKey: capped.pub()})
	if !errors.Is(err, sensorpairing.ErrCapacity) {
		t.Fatalf("cap: %v", err)
	}
	f.svc.SetMaxOpen(sensorpairing.DefaultMaxOpen)

	// Code guessing locks lookups for the user (threat 4).
	for range sensorpairing.LookupFailureLimit {
		_, _ = f.svc.Lookup(ctx, a, "0000-0000")
	}
	if _, err := f.svc.Lookup(ctx, a, "0000-0001"); !errors.Is(err, sensorpairing.ErrLookupLocked) {
		t.Fatalf("lookup lockout: %v", err)
	}
}

package sensorpairing_test

// Shared sensor enrollment with an instance enrollment token, end to end
// against a migrated database (docs/rfcs/RFC-100-shared-sensors.md §7): the
// token is single use, short-lived and refused uniformly; redeeming it
// yields a shared sensor (no tenant, trusted, least-privilege grant) through
// the key-bound pairing exchange, never a tenant context; an organization
// administrator can neither approve nor deny such a request; every step
// writes a console audit row.

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
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

type auditSink struct {
	mu   sync.Mutex
	rows []*admin.AuditLog
}

func (a *auditSink) Create(_ context.Context, l *admin.AuditLog) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, l)
	return nil
}

func (a *auditSink) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.rows))
	for _, r := range a.rows {
		out = append(out, r.Action)
	}
	return out
}

func (f *fixture) issue(sink *auditSink, ttl time.Duration) string {
	f.t.Helper()
	f.svc.SetAdminAudit(sink)
	out, err := f.svc.IssueInstanceToken(context.Background(), sensorpairing.IssueInstanceTokenInput{
		Name: "central-01", Reason: "bundled scanner", TTL: ttl, IP: "198.51.100.1"})
	if err != nil {
		f.t.Fatalf("issue: %v", err)
	}
	f.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.db.ExecContext(ctx, `DELETE FROM sensors WHERE id IN (SELECT sensor_id FROM sensor_pairings WHERE instance_token_id = $1)`, out.ID.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM sensor_pairings WHERE instance_token_id = $1`, out.ID.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM instance_enrollment_tokens WHERE id = $1`, out.ID.String())
	})
	return out.Token
}

func (f *fixture) startWithToken(s *sensor, token string) error {
	resp, err := f.svc.Start(context.Background(), sensorpairing.StartInput{
		Request: pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(s.pub()),
			Commitment: pairing.Encode(s.commitment), EnrollmentToken: token,
			Host: pairing.HostFacts{Hostname: "central01", OS: "linux", Arch: "amd64", SensorVersion: "0.24.0"}},
		PublicKey: s.pub(), SourceIP: net.ParseIP("203.0.113.20"),
	})
	if err != nil {
		return err
	}
	if s.platformPub, s.pNonce, err = pairing.VerifyStart(resp, s.pub(), s.commitment, "", sensorsig.Thumbprint); err != nil {
		f.t.Fatalf("platform signature: %v", err)
	}
	if resp.UserCode != "" {
		f.t.Fatalf("an instance enrollment returned a user code %q", resp.UserCode)
	}
	s.resp = resp
	return nil
}

func TestInstanceEnrollment_SharedSensorEndToEnd_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-inst-a")
	sink := &auditSink{}
	token := f.issue(sink, 0)
	if _, ok := sensorkey.Valid(token); !ok || !strings.HasPrefix(token, sensorkey.PrefixEnrollmentToken) {
		t.Fatalf("issued token %q is not a checksummed octe_ token", token)
	}
	// Only the keyed hash is stored.
	var stored int
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM instance_enrollment_tokens WHERE token_hash = $1 OR token_hash = $2`,
		token, strings.TrimPrefix(token, sensorkey.PrefixEnrollmentToken)).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("the token is stored in clear (%d, %v)", stored, err)
	}

	s := newSensor(1)
	if err := f.startWithToken(s, token); err != nil {
		t.Fatalf("start: %v", err)
	}
	if st := f.status(s); st.Status != pairing.StatusPending || st.Identity != nil {
		t.Fatalf("before reveal: %+v", st)
	}
	id, _ := shared.IDFromString(s.resp.PairingID)

	// An organization administrator cannot approve or deny the request,
	// with or without a code.
	if _, err := f.svc.Approve(ctx, a, id, approve("")); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("organization approval of an instance request: %v", err)
	}
	if err := f.svc.Deny(ctx, a, id); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("organization denial of an instance request: %v", err)
	}

	f.reveal(s)
	f.reveal(s) // a retried reveal is harmless
	st := f.status(s)
	if st.Status != pairing.StatusApproved || st.Identity == nil {
		t.Fatalf("after reveal: %+v", st)
	}
	ident := st.Identity
	if ident.TenantID != "" || ident.Scope != pairing.ScopeInstance || ident.Name != "central-01" || ident.KeyID != s.thumb() {
		t.Fatalf("identity: %+v", ident)
	}
	// The key is pending until the sensor confirms.
	if _, _, err := f.sensors.SigningIdentity(ctx, s.thumb(), true); err == nil {
		t.Fatal("a pending key authenticated")
	}
	if done, err := f.confirm(s, ident); err != nil || done.Status != pairing.StatusCompleted {
		t.Fatalf("confirm: %+v %v", done, err)
	}

	sid, _ := shared.IDFromString(ident.SensorID)
	var (
		scope, trust, profile, network string
		tenant, grantTenant, keyTenant *string
		creds, push                    bool
		tier                           int
		jobTypes                       string
	)
	if err := f.db.QueryRowContext(ctx, `SELECT s.scope, s.tenant_id::text, s.trust_level, g.tenant_id::text, g.profile,
			g.allow_credentials, g.allow_push_ingest, g.tier_ceiling, g.target_network, array_to_string(g.job_types, ','),
			k.tenant_id::text
		FROM sensors s JOIN sensor_grants g ON g.sensor_id = s.id JOIN sensor_keys k ON k.sensor_id = s.id
		WHERE s.id = $1 AND k.status = 'active'`, sid.String()).
		Scan(&scope, &tenant, &trust, &grantTenant, &profile, &creds, &push, &tier, &network, &jobTypes, &keyTenant); err != nil {
		t.Fatalf("read shared sensor: %v", err)
	}
	if scope != "instance" || tenant != nil || grantTenant != nil || keyTenant != nil || trust != "trusted" {
		t.Fatalf("sensor scope=%s tenant=%v grant tenant=%v key tenant=%v trust=%s", scope, tenant, grantTenant, keyTenant, trust)
	}
	if creds || push || tier > 1 || network != "public" || jobTypes != "retest,scan,validate" {
		t.Fatalf("grant is not least privilege: creds=%v push=%v tier=%d network=%s jobs=%s", creds, push, tier, network, jobTypes)
	}

	// The signed key authenticates the sensor, never into a tenant.
	sid2, _, err := f.sensors.SigningIdentity(ctx, s.thumb(), true)
	if err != nil || sid2.Sensor == nil || !sid2.Sensor.IsShared() || sid2.Sensor.TenantID != nil || sid2.Sensor.ID != sid {
		t.Fatalf("signing identity: %+v %v", sid2.Sensor, err)
	}
	// The tenant plane answers not found.
	if got, err := postgres.NewSensorRepository(&postgres.DB{DB: f.db}).GetByTenantAndID(ctx, a.TenantID, sid); err == nil && got != nil {
		t.Fatal("an organization reads the shared sensor")
	}

	want := []string{admin.AuditActionInstanceTokenCreate, admin.AuditActionInstanceTokenRedeem,
		admin.AuditActionSharedSensorEnrolled, admin.AuditActionSharedSensorConfirmed}
	if got := sink.actions(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("console audit rows %v, want %v", got, want)
	}
	for _, r := range sink.rows {
		if r.Severity != admin.SeverityHigh || r.AdminEmail == "" {
			t.Fatalf("audit row %s: severity %s email %q", r.Action, r.Severity, r.AdminEmail)
		}
		for k, v := range r.RequestBody {
			if s, ok := v.(string); ok && strings.Contains(s, token) {
				t.Fatalf("audit row %s carries the token in %s", r.Action, k)
			}
		}
	}

	// Single use: the same token is refused for another key, and nothing is
	// written for it.
	if err := f.startWithToken(newSensor(2), token); !errors.Is(err, sensorpairing.ErrEnrollmentRefused) {
		t.Fatalf("second use: %v", err)
	}
	var pairings int
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_pairings p JOIN instance_enrollment_tokens t ON t.id = p.instance_token_id
		WHERE t.token_hash = (SELECT token_hash FROM instance_enrollment_tokens WHERE id = (
			SELECT instance_token_id FROM sensor_pairings WHERE id = $1))`, id.String()).Scan(&pairings)
	if pairings != 1 {
		t.Fatalf("pairings for the token: %d", pairings)
	}
}

func TestInstanceEnrollment_RefusedUniformly_DB(t *testing.T) {
	f := newFixture(t)
	sink := &auditSink{}
	expiring := f.issue(sink, 5*time.Minute)

	unknown, _ := sensorkey.New(sensorkey.PrefixEnrollmentToken)
	sensorKey, _ := sensorkey.New(sensorkey.PrefixSensorKey)
	for name, tok := range map[string]string{
		"unknown":    unknown,
		"malformed":  "octe_short",
		"sensor key": sensorKey,
		"tampered":   expiring[:len(expiring)-1] + "x",
	} {
		if err := f.startWithToken(newSensor(3), tok); !errors.Is(err, sensorpairing.ErrEnrollmentRefused) {
			t.Fatalf("%s token: %v", name, err)
		}
	}
	// A token with an expectation code or a re-pair is an invalid request.
	s := newSensor(4)
	_, err := f.svc.Start(context.Background(), sensorpairing.StartInput{
		Request: pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(s.pub()),
			Commitment: pairing.Encode(s.commitment), EnrollmentToken: expiring, SensorID: shared.NewID().String()},
		PublicKey: s.pub()})
	if !errors.Is(err, sensorpairing.ErrInvalid) {
		t.Fatalf("token with a re-pair: %v", err)
	}
	// Expired: refused, and stays unspent.
	f.now = f.now.Add(6 * time.Minute)
	if err := f.startWithToken(newSensor(5), expiring); !errors.Is(err, sensorpairing.ErrEnrollmentRefused) {
		t.Fatalf("expired token: %v", err)
	}
	var used *time.Time
	if err := f.db.QueryRowContext(context.Background(), `SELECT used_at FROM instance_enrollment_tokens
		WHERE created_by_email = 'bootstrap' AND reason = 'bundled scanner' ORDER BY created_at DESC LIMIT 1`).Scan(&used); err != nil || used != nil {
		t.Fatalf("expired token used_at %v (%v)", used, err)
	}
	// Refusals write no redemption row.
	for _, a := range sink.actions() {
		if a != admin.AuditActionInstanceTokenCreate {
			t.Fatalf("refused redemption wrote %s", a)
		}
	}
}

func TestInstanceEnrollment_IssueAndRegisterLimits_DB(t *testing.T) {
	f := newFixture(t)
	f.svc.SetAdminAudit(&auditSink{})
	ctx := context.Background()
	for name, in := range map[string]sensorpairing.IssueInstanceTokenInput{
		"no reason":   {Reason: "  "},
		"over 1 hour": {Reason: "r", TTL: 61 * time.Minute},
		"too short":   {Reason: "r", TTL: time.Minute},
		"long reason": {Reason: strings.Repeat("r", 1001)},
	} {
		if _, err := f.svc.IssueInstanceToken(ctx, in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// The install generates octe_ and 49 letters or digits (no checksum).
	gen := sensorkey.PrefixEnrollmentToken + strings.Repeat("aB3", 16) + "z"
	for _, bad := range []string{"", "octe_" + strings.Repeat("a", 48), "octs_" + strings.Repeat("a", 49), "octe_" + strings.Repeat("a", 48) + "-"} {
		if _, err := f.svc.RegisterInstanceToken(ctx, bad, sensorpairing.IssueInstanceTokenInput{Reason: "install"}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("register %q: %v", bad, err)
		}
	}
	out, err := f.svc.RegisterInstanceToken(ctx, gen, sensorpairing.IssueInstanceTokenInput{Reason: "install"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id IN (SELECT sensor_id FROM sensor_pairings WHERE instance_token_id = $1)`, out.ID.String())
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM sensor_pairings WHERE instance_token_id = $1`, out.ID.String())
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM instance_enrollment_tokens WHERE id = $1`, out.ID.String())
	})
	if !out.ExpiresAt.After(f.now) || out.ExpiresAt.After(f.now.Add(time.Hour+time.Second)) {
		t.Fatalf("expiry %v", out.ExpiresAt)
	}
	// The same value cannot be registered twice.
	if _, err := f.svc.RegisterInstanceToken(ctx, gen, sensorpairing.IssueInstanceTokenInput{Reason: "install"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second registration: %v", err)
	}
	if err := f.startWithToken(newSensor(6), gen); err != nil {
		t.Fatalf("start with a registered token: %v", err)
	}
	// The database refuses a lifetime over one hour whatever the caller.
	if _, err := f.db.ExecContext(ctx, `INSERT INTO instance_enrollment_tokens (token_hash, reason, created_by_email, created_at, expires_at)
		VALUES ('x', 'r', 'e', now(), now() + interval '2 hours')`); err == nil {
		t.Fatal("a two-hour token was stored")
	}
}

// The host facts a redeeming sensor claims reach the console audit rows
// only as the known fields, stripped of control and bidi characters and
// bounded: an attacker holding a token cannot write free-form blobs or
// terminal escapes into the audit log.
func TestInstanceEnrollment_AuditHostFactsSanitized_DB(t *testing.T) {
	f := newFixture(t)
	sink := &auditSink{}
	token := f.issue(sink, 0)
	s := newSensor(7)
	long := strings.Repeat("h", 5000)
	_, err := f.svc.Start(context.Background(), sensorpairing.StartInput{
		Request: pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(s.pub()),
			Commitment: pairing.Encode(s.commitment), EnrollmentToken: token,
			Host: pairing.HostFacts{Hostname: long, OS: "linux\x1b[31m\u202e", Arch: "amd64\n\r", Product: "p\x00q"}},
		PublicKey: s.pub(), SourceIP: net.ParseIP("203.0.113.21"),
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	var facts map[string]string
	for _, r := range sink.rows {
		if r.Action == admin.AuditActionInstanceTokenRedeem {
			raw, _ := r.RequestBody["host_facts"].(map[string]any)
			facts = map[string]string{}
			for k, v := range raw {
				s, ok := v.(string)
				if !ok {
					t.Fatalf("host fact %s is not a string: %T", k, v)
				}
				facts[k] = s
			}
		}
	}
	if facts == nil {
		t.Fatalf("no host facts in the redeem row: %+v", sink.rows)
	}
	for k, v := range facts {
		if len(v) > 128 || strings.ContainsAny(v, "\x1b\x00\n\r\u202e") {
			t.Fatalf("host fact %s not sanitized: %q", k, v)
		}
		switch k {
		case "hostname", "os", "arch", "sensor_version", "sdk_version", "product", "instance_id", "name":
		default:
			t.Fatalf("unexpected host fact key %q", k)
		}
	}
	if facts["os"] != "linux[31m" || facts["arch"] != "amd64" || facts["product"] != "pq" || len(facts["hostname"]) != 128 {
		t.Fatalf("facts %+v", facts)
	}
}

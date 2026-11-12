package sensorpairing_test

// An approval that also trusts the sensor and states its networks
// (approve_setup.go): who may, for which requests and profiles, and that a
// refusal creates nothing while a success commits the sensor, its grant and
// its zone together.

import (
	"context"
	"errors"
	"sync"
	"testing"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/sensorgrant"
	"github.com/openctemio/openctem/server/internal/app/sensorpairing"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/scanzone"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fixedAdmins struct{ ids []shared.ID }

func (a fixedAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return a.ids, nil
}

type notices struct {
	mu   sync.Mutex
	list []notificationdom.NotificationParams
}

func (n *notices) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.list = append(n.list, p)
	return nil
}

// withZones wires the zone store and removes the org's zones on cleanup.
func (f *fixture) withZones(a sensorpairing.Actor) *postgres.ScanZoneRepository {
	repo := postgres.NewScanZoneRepository(&postgres.DB{DB: f.db})
	f.svc.SetZones(repo)
	f.t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM scan_zones WHERE tenant_id = $1`, a.TenantID.String())
	})
	return repo
}

// expected starts a sensor on a console code of a's organization.
func (f *fixture) expected(a sensorpairing.Actor, name string) (shared.ID, *sensor) {
	f.t.Helper()
	exp, err := f.svc.Expect(context.Background(), a, sensorpairing.ExpectInput{Name: name})
	if err != nil {
		f.t.Fatalf("expect: %v", err)
	}
	s := newSensor(0)
	f.start(s, exp.Code, "")
	f.reveal(s)
	id, _ := shared.IDFromString(exp.ID)
	return id, s
}

func (f *fixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestPairing_ApproveTrustedWithNetworks_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	grants := f.withGrants()
	a := f.org("org-trust-net")
	a.CanWiden, a.CanWriteZones = true, true
	zones := f.withZones(a)

	id, s := f.expected(a, "branch-scanner")
	v, err := f.svc.GetExpectation(ctx, a, id)
	if err != nil || !v.TrustEligible {
		t.Fatalf("an expectation of the organization is trust eligible: %+v %v", v, err)
	}
	in := approve(a, "")
	in.Profile, in.Trusted, in.Ranges = sensordom.ProfileInternalScanner, true, []string{"10.20.0.0/16"}
	if _, err := f.approveP(ctx, a, id, in); err != nil {
		t.Fatalf("approve: %v", err)
	}
	sid := f.status(s).Identity.SensorID
	g := f.grant(grants, a.TenantID, sid)
	if g.TrustLevel != sensordom.TrustTrusted || g.Profile != sensordom.ProfileInternalScanner || len(g.ZoneIDs) != 1 {
		t.Fatalf("grant: %+v", g)
	}
	list, err := zones.List(ctx, a.TenantID)
	if err != nil || len(list) != 1 {
		t.Fatalf("zones: %v %v", list, err)
	}
	z := list[0]
	if z.Name != "dmz-01 networks" || len(z.Ranges) != 1 || z.Ranges[0].String() != "10.20.0.0/16" ||
		len(z.SensorIDs) != 1 || z.SensorIDs[0].String() != sid || g.ZoneIDs[0] != z.ID {
		t.Fatalf("zone: %+v (grant zones %v)", z, g.ZoneIDs)
	}

	// A second sensor stating the same networks joins that zone.
	id2, s2 := f.expected(a, "branch-scanner-2")
	in2 := approve(a, "")
	in2.Name, in2.Profile, in2.Ranges = "dmz-02", sensordom.ProfileInternalScanner, []string{"10.20.0.0/16"}
	if _, err := f.approveP(ctx, a, id2, in2); err != nil {
		t.Fatalf("approve second: %v", err)
	}
	list, _ = zones.List(ctx, a.TenantID)
	if len(list) != 1 || len(list[0].SensorIDs) != 2 {
		t.Fatalf("second sensor did not join the existing zone: %+v", list)
	}
	if g := f.grant(grants, a.TenantID, f.status(s2).Identity.SensorID); g.TrustLevel != sensordom.TrustNew {
		t.Fatalf("trusted without asking: %+v", g)
	}
}

func TestPairing_ApproveTrustedRefusals_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.withGrants()
	a := f.org("org-trust-refusals")
	a.CanWiden, a.CanWriteZones = true, true
	f.withZones(a)
	sensorsOf := func() int { return f.count(`SELECT count(*) FROM sensors WHERE tenant_id = $1`, a.TenantID.String()) }
	zonesOf := func() int {
		return f.count(`SELECT count(*) FROM scan_zones WHERE tenant_id = $1`, a.TenantID.String())
	}

	refused := func(name string, actor sensorpairing.Actor, id shared.ID, in sensorpairing.ApproveInput, want error) {
		t.Helper()
		before, zb := sensorsOf(), zonesOf()
		if _, err := f.approveP(ctx, actor, id, in); !errors.Is(err, want) {
			t.Fatalf("%s: err = %v, want %v", name, err, want)
		}
		if sensorsOf() != before || zonesOf() != zb {
			t.Fatalf("%s: a refused approval created a sensor or a zone", name)
		}
	}

	// A sensor-started code (/activate): never trusted at approval.
	fwd := newSensor(0)
	f.start(fwd, "", "")
	f.reveal(fwd)
	fid, _ := shared.IDFromString(fwd.resp.PairingID)
	if v, err := f.svc.Lookup(ctx, a, fwd.resp.UserCode); err != nil || v.TrustEligible {
		t.Fatalf("a sensor-started request is trust eligible: %+v %v", v, err)
	}
	in := approve(a, fwd.resp.UserCode)
	in.Profile, in.Trusted = sensordom.ProfileInternalScanner, true
	refused("forward code", a, fid, in, sensorpairing.ErrTrustNotAllowed)

	id, _ := f.expected(a, "x")
	// Profiles with credentials or push ingest keep the separate promotion.
	for _, profile := range []string{sensordom.ProfileAuthenticatedScanner, sensordom.ProfileCollector, sensordom.ProfileCIRunner} {
		in := approve(a, "")
		in.Profile, in.Trusted = profile, true
		refused(profile, a, id, in, sensorpairing.ErrTrustNotAllowed)
	}
	// Without sensors:grant:widen.
	noWiden := a
	noWiden.CanWiden = false
	in = approve(a, "")
	in.Profile, in.Trusted = sensordom.ProfileInternalScanner, true
	refused("no widen", noWiden, id, in, sensorgrant.ErrWidenForbidden)
	// Networks without sensors:zones:write, public networks, a profile that
	// scans no zone.
	noZones := a
	noZones.CanWriteZones = false
	in = approve(a, "")
	in.Profile, in.Ranges = sensordom.ProfileInternalScanner, []string{"10.0.0.0/16"}
	refused("no zones permission", noZones, id, in, sensorpairing.ErrZonesForbidden)
	for name, ranges := range map[string][]string{
		"public":    {"203.0.113.0/24"},
		"cgnat":     {"100.64.0.0/16"},
		"deny list": {"169.254.169.254"},
		"too wide":  {"10.0.0.0/7"},
	} {
		in := approve(a, "")
		in.Profile, in.Ranges = sensordom.ProfileInternalScanner, ranges
		refused(name, a, id, in, sensorpairing.ErrRangesInvalid)
	}
	in = approve(a, "")
	in.Profile, in.Ranges = sensordom.ProfileEASMExternal, []string{"10.0.0.0/16"}
	refused("easm with networks", a, id, in, sensorpairing.ErrRangesInvalid)

	// Another organization cannot approve this organization's expectation.
	b := f.org("org-trust-other")
	b.CanWiden, b.CanWriteZones = true, true
	in = approve(b, "")
	in.OrganizationID = b.TenantID.String()
	in.Profile, in.Trusted, in.Ranges = sensordom.ProfileInternalScanner, true, []string{"10.0.0.0/16"}
	refused("other organization", b, id, in, sensorpairing.ErrNotFound)

	// The request still approves once the approver drops what was refused.
	in = approve(a, "")
	in.Profile = sensordom.ProfileInternalScanner
	if _, err := f.approveP(ctx, a, id, in); err != nil {
		t.Fatalf("plain approval after refusals: %v", err)
	}
}

func TestTrustEligible(t *testing.T) {
	tid, other, uid, tok := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	base := func() *sensordom.Pairing {
		return &sensordom.Pairing{Mode: sensordom.PairingReverse, TenantID: &tid, CreatedBy: &uid}
	}
	if !sensorpairing.TrustEligible(base(), tid) {
		t.Fatal("a console expectation of the organization is eligible")
	}
	for name, mut := range map[string]func(p *sensordom.Pairing){
		"forward":          func(p *sensordom.Pairing) { p.Mode = sensordom.PairingForward },
		"no creator":       func(p *sensordom.Pairing) { p.CreatedBy = nil },
		"tenantless":       func(p *sensordom.Pairing) { p.TenantID = nil },
		"other tenant":     func(p *sensordom.Pairing) { p.TenantID = &other },
		"enrollment token": func(p *sensordom.Pairing) { p.EnrollmentTokenID = &tok },
		"instance token":   func(p *sensordom.Pairing) { p.InstanceTokenID = &tok },
		"re-pair":          func(p *sensordom.Pairing) { p.RepairSensorID = &tok },
	} {
		p := base()
		mut(p)
		if sensorpairing.TrustEligible(p, tid) {
			t.Errorf("%s is eligible", name)
		}
	}
}

// A trusted approval is audited like a promotion: one high-severity
// sensor.grant_changed row marked at_approval, and every administrator is
// told. An approval that does not trust the sensor writes neither.
func TestPairing_ApproveTrustedAuditsAndNotifies_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.withTenantsAndAudit()
	pg := &postgres.DB{DB: f.db}
	grantSvc := sensorgrant.NewService(postgres.NewSensorGrantRepository(pg), postgres.NewSensorRepository(pg), logger.NewNop())
	grantSvc.SetAudit(auditapp.NewAuditService(postgres.NewAuditRepository(pg), logger.NewNop()))
	admin := shared.NewID()
	sink := &notices{}
	grantSvc.SetNotifications(fixedAdmins{ids: []shared.ID{admin}}, sink)
	f.svc.SetApprovalHook(grantSvc)
	a := f.org("org-trust-audit")
	a.CanWiden = true
	f.cleanAudit(a.TenantID)

	count := func() int {
		return f.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'sensor.grant_changed'
			AND severity = 'high' AND metadata->>'at_approval' = 'true'`, a.TenantID.String())
	}

	// Not trusted: nothing to audit, nobody to tell.
	id0, _ := f.expected(a, "plain-scanner")
	in0 := approve(a, "")
	in0.Profile = sensordom.ProfileInternalScanner
	if _, err := f.approveP(ctx, a, id0, in0); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if count() != 0 || len(sink.list) != 0 {
		t.Fatalf("an untrusted approval wrote %d audit rows and %d notices", count(), len(sink.list))
	}

	id, _ := f.expected(a, "trusted-scanner")
	in := approve(a, "")
	in.Name, in.Profile, in.Trusted = "trusted-01", sensordom.ProfileInternalScanner, true
	if _, err := f.approveP(ctx, a, id, in); err != nil {
		t.Fatalf("approve trusted: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("high-severity at_approval sensor.grant_changed rows = %d, want 1", n)
	}
	if len(sink.list) != 1 || sink.list[0].AudienceID == nil || *sink.list[0].AudienceID != admin ||
		sink.list[0].Severity != "high" || sink.list[0].TenantID != a.TenantID {
		t.Fatalf("admin notice: %+v", sink.list)
	}
}

// The zone limit is counted again inside the approval transaction, so a
// zone created after the planning step cannot push the tenant past it.
func TestPairing_CreateWithSensorTxRecountsZones_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-zone-limit")
	repo := f.withZones(a)
	f.exec(`INSERT INTO scan_zones (id, tenant_id, name, description, is_default, ranges)
		SELECT gen_random_uuid(), $1, 'z' || g, '', false, ARRAY['10.0.0.0/8']::cidr[] FROM generate_series(1, $2) g`,
		a.TenantID.String(), scanzone.MaxZonesPerTenant)
	uid := a.UserID
	z, err := scanzone.NewZone(a.TenantID, "one too many", "", false, []string{"10.1.0.0/16"}, &uid)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := repo.CreateWithSensorTx(ctx, tx, z, shared.NewID(), &uid); !errors.Is(err, scanzone.ErrTooManyZones) {
		t.Fatalf("err = %v, want ErrTooManyZones", err)
	}
}

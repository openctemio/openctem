package sensorpairing_test

// Re-pair started from the console (RFC-052 §4.6; research note 352 D1-D4):
// only a code the console made for a sensor re-pairs it, the registration is
// kept, the old key stops at approval, leased commands are taken back, and
// another organization can neither start nor approve it.

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type eventLog struct{ types []sensordom.EventType }

func (l *eventLog) RecordEvents(_ context.Context, evs []sensordom.Event) {
	for _, e := range evs {
		l.types = append(l.types, e.Type)
	}
}

type fakeReleaser struct {
	calls []shared.ID
}

func (r *fakeReleaser) ReleaseHeldBySensor(_ context.Context, _, sensorID shared.ID, requeue, fail string) ([]commanddom.ReleasedCommand, error) {
	if requeue != commanddom.SensorKeyReplacedRequeuedMessage || fail != commanddom.SensorKeyReplacedFailedMessage {
		return nil, errors.New("unexpected messages")
	}
	r.calls = append(r.calls, sensorID)
	return []commanddom.ReleasedCommand{{ID: shared.NewID(), Requeued: true}}, nil
}

// paired pairs a fresh sensor into the actor's organization (forward mode)
// and returns it with its sensor id.
func (f *fixture) paired(a sensorpairing.Actor, name string) (*sensor, string) {
	f.t.Helper()
	ctx := context.Background()
	s := newSensor(0)
	f.start(s, "", "")
	f.reveal(s)
	id, _ := shared.IDFromString(s.resp.PairingID)
	in := approve(a, s.resp.UserCode)
	in.Name = name
	if _, err := f.svc.Approve(ctx, a, id, in); err != nil {
		f.t.Fatalf("approve %s: %v", name, err)
	}
	st := f.status(s)
	if _, err := f.confirm(s, st.Identity); err != nil {
		f.t.Fatalf("confirm %s: %v", name, err)
	}
	return s, st.Identity.SensorID
}

func (f *fixture) expectation(a sensorpairing.Actor, id string) *sensorpairing.View {
	f.t.Helper()
	pid, _ := shared.IDFromString(id)
	v, err := f.svc.GetExpectation(context.Background(), a, pid)
	if err != nil {
		f.t.Fatalf("get expectation: %v", err)
	}
	return v
}

func TestPairing_ConsoleRepair_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rel := &fakeReleaser{}
	f.svc.SetCommandReleaser(rel)
	events := &eventLog{}
	f.svc.SetEvents(events)
	a, b := f.org("org-repair-a"), f.org("org-repair-b")
	old, sensorID := f.paired(a, "dmz-01")
	sid, _ := shared.IDFromString(sensorID)
	f.exec(`UPDATE sensors SET hostname = 'old-host', ip_address = '192.0.2.10', version = '0.30.0' WHERE id = $1`, sensorID)

	// The request shape: a reason is required, and a re-pair keeps the
	// registration (no name, zones or profile).
	if _, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{RepairSensorID: &sid}); !errors.Is(err, sensorpairing.ErrInvalid) {
		t.Fatalf("re-pair without a reason: %v", err)
	}
	if _, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{RepairSensorID: &sid, RepairReason: "because"}); !errors.Is(err, sensorpairing.ErrInvalid) {
		t.Fatalf("re-pair with an unknown reason: %v", err)
	}
	if _, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{RepairSensorID: &sid, RepairReason: sensordom.RepairLostIdentity, Name: "x"}); !errors.Is(err, sensorpairing.ErrInvalid) {
		t.Fatalf("re-pair that renames: %v", err)
	}
	if _, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{RepairReason: sensordom.RepairLostIdentity}); !errors.Is(err, sensorpairing.ErrInvalid) {
		t.Fatalf("a reason without a sensor: %v", err)
	}
	// Another organization cannot start a re-pair of this sensor.
	if _, err := f.svc.Expect(ctx, b, sensorpairing.ExpectInput{RepairSensorID: &sid, RepairReason: sensordom.RepairLostIdentity}); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("cross-tenant re-pair code: %v", err)
	}

	first, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{RepairSensorID: &sid, RepairReason: sensordom.RepairLostIdentity})
	if err != nil {
		t.Fatalf("re-pair code: %v", err)
	}
	// A newer re-pair code closes the earlier one.
	exp, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{RepairSensorID: &sid, RepairReason: sensordom.RepairHostMoved})
	if err != nil {
		t.Fatalf("second re-pair code: %v", err)
	}
	if v := f.expectation(a, first.ID); v.Status != string(sensordom.PairingExpired) {
		t.Fatalf("earlier re-pair code still open: %s", v.Status)
	}
	// The old key keeps working until the re-pair is approved.
	if _, _, err := f.sensors.SigningIdentity(ctx, old.thumb(), true); err != nil {
		t.Fatalf("old key stopped before approval: %v", err)
	}

	// A sensor that lost its volume: a fresh key, no sensor id of its own.
	fresh := newSensor(0)
	f.start(fresh, exp.Code, "")
	f.reveal(fresh)
	v := f.expectation(a, exp.ID)
	if v.RepairSensorID != sensorID || v.RepairSensor != "dmz-01" || v.RepairReason != sensordom.RepairHostMoved {
		t.Fatalf("re-pair view: %+v", v)
	}
	if v.RepairBefore == nil || v.RepairBefore.Hostname != "old-host" || v.RepairBefore.IPAddress != "192.0.2.10" || v.RepairBefore.Version != "0.30.0" {
		t.Fatalf("before facts: %+v", v.RepairBefore)
	}
	// Another organization cannot read or approve it.
	pid, _ := shared.IDFromString(exp.ID)
	if _, err := f.svc.GetExpectation(ctx, b, pid); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	if _, err := f.svc.Approve(ctx, b, pid, approve(b, "")); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("cross-tenant approve: %v", err)
	}
	// Step-up is required as for every approval.
	in := approve(a, "")
	in.RepairSensorID = sensorID
	f.stepUp.ok = false
	if _, err := f.svc.Approve(ctx, a, pid, in); err == nil {
		t.Fatal("re-pair approved without step-up")
	}
	f.stepUp.ok = true
	// The approval must name the sensor it re-pairs.
	if _, err := f.svc.Approve(ctx, a, pid, approve(a, "")); !errors.Is(err, sensorpairing.ErrRepairNotAcknowledged) {
		t.Fatalf("re-pair approved without naming the sensor: %v", err)
	}
	wrong := approve(a, "")
	wrong.RepairSensorID = shared.NewID().String()
	if _, err := f.svc.Approve(ctx, a, pid, wrong); !errors.Is(err, sensorpairing.ErrRepairNotAcknowledged) {
		t.Fatalf("re-pair approved naming another sensor: %v", err)
	}
	in.Name = "renamed" // ignored: the registration is kept
	if _, err := f.svc.Approve(ctx, a, pid, in); err != nil {
		t.Fatalf("re-pair approve: %v", err)
	}
	// The old key stops at approval; the sensor id and name stay.
	if _, _, err := f.sensors.SigningIdentity(ctx, old.thumb(), true); err == nil {
		t.Fatal("old key authenticates after the re-pair")
	}
	st := f.status(fresh)
	if st.Identity == nil || st.Identity.SensorID != sensorID || !st.Identity.Repair || st.Identity.Name != "dmz-01" {
		t.Fatalf("re-pair identity: %+v", st.Identity)
	}
	if _, err := f.confirm(fresh, st.Identity); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	ident, _, err := f.sensors.SigningIdentity(ctx, fresh.thumb(), true)
	if err != nil || ident.Sensor.ID.String() != sensorID || ident.Sensor.Name != "dmz-01" {
		t.Fatalf("new key: %v", err)
	}
	// The leased commands were taken back, once, for this sensor.
	if len(rel.calls) != 1 || rel.calls[0] != sid {
		t.Fatalf("release calls: %v", rel.calls)
	}
	var n int
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensors WHERE tenant_id = $1`, a.TenantID.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("a re-pair created a sensor: %d sensors", n)
	}
	started, repaired := 0, 0
	for _, e := range events.types {
		switch e {
		case sensordom.EventRepairStarted:
			started++
		case sensordom.EventRepaired:
			repaired++
		}
	}
	if started != 2 || repaired != 1 {
		t.Fatalf("timeline: %d started, %d repaired (%v)", started, repaired, events.types)
	}
}

// An ordinary code never becomes a re-pair because the sensor names a
// sensor: the request adds a sensor, and the named sensor keeps its key.
func TestPairing_OrdinaryCodeCannotTargetASensor_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-hijack")
	victim, victimID := f.paired(a, "victim")

	exp, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{Name: "new-one"})
	if err != nil {
		t.Fatal(err)
	}
	intruder := newSensor(0)
	f.start(intruder, exp.Code, victimID) // names the victim
	f.reveal(intruder)
	v := f.expectation(a, exp.ID)
	if v.RepairSensorID != "" || v.RepairBefore != nil {
		t.Fatalf("an ordinary code became a re-pair: %+v", v)
	}
	pid, _ := shared.IDFromString(exp.ID)
	// Naming a sensor on an approval that adds one is refused too.
	bad := approve(a, "")
	bad.RepairSensorID = victimID
	if _, err := f.svc.Approve(ctx, a, pid, bad); !errors.Is(err, sensorpairing.ErrRepairNotAcknowledged) {
		t.Fatalf("approval naming a sensor for a new one: %v", err)
	}
	if _, err := f.svc.Approve(ctx, a, pid, approve(a, "")); err != nil {
		t.Fatalf("approve: %v", err)
	}
	st := f.status(intruder)
	if st.Identity == nil || st.Identity.SensorID == victimID || st.Identity.Repair {
		t.Fatalf("identity: %+v", st.Identity)
	}
	if _, _, err := f.sensors.SigningIdentity(ctx, victim.thumb(), true); err != nil {
		t.Fatalf("the named sensor lost its key: %v", err)
	}
}

// Revoking a sensor's last active key ("Revoke the current key now" in the
// re-pair dialog) takes back its leased commands at once.
func TestPairing_RevokingLastKeyReleasesCommands_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rel := &fakeReleaser{}
	f.sensors.SetHolderReleaser(rel)
	a, b := f.org("org-revoke-a"), f.org("org-revoke-b")
	s, sensorID := f.paired(a, "edge-01")
	sid, _ := shared.IDFromString(sensorID)
	var keyID string
	if err := f.db.QueryRowContext(ctx, `SELECT id FROM sensor_keys WHERE sensor_id = $1 AND status = 'active'`, sensorID).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	kid, _ := shared.IDFromString(keyID)
	// Another organization cannot revoke it.
	if err := f.sensors.RevokeSigningKey(ctx, auditContextOf(b), b.TenantID, sid, kid); err == nil {
		t.Fatal("cross-tenant key revocation")
	}
	if len(rel.calls) != 0 {
		t.Fatalf("released on a refused revocation: %v", rel.calls)
	}
	if err := f.sensors.RevokeSigningKey(ctx, auditContextOf(a), a.TenantID, sid, kid); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := f.sensors.SigningIdentity(ctx, s.thumb(), true); err == nil {
		t.Fatal("revoked key authenticates")
	}
	if len(rel.calls) != 1 || rel.calls[0] != sid {
		t.Fatalf("release calls: %v", rel.calls)
	}
}

func auditContextOf(a sensorpairing.Actor) auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: a.TenantID.String(), ActorID: a.UserID.String(), ActorEmail: a.Email}
}

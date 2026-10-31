package sensorpairing_test

// Refusals reach the console's waiting step, and an approval the sensor
// never confirmed leaves no sensor behind (research note 352 D6, D9).

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (f *fixture) view(a sensorpairing.Actor, id string) *sensorpairing.View {
	f.t.Helper()
	pid, _ := shared.IDFromString(id)
	v, err := f.svc.GetExpectation(context.Background(), a, pid)
	if err != nil {
		f.t.Fatalf("get expectation: %v", err)
	}
	return v
}

func TestPairing_RefusalsReachTheWaitingStep_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.org("org-refusal-a"), f.org("org-refusal-b")
	exp, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{Name: "edge"})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing yet.
	if v := f.view(a, exp.ID); v.LastRefusal != nil {
		t.Fatalf("refusal before any attempt: %+v", v.LastRefusal)
	}
	// A sensor with a wrong clock (its signature verified, the handler
	// records it).
	skewed := newSensor(0)
	f.svc.RecordRefusal(ctx, sensorpairing.Refusal{Code: exp.Code, PublicKey: skewed.pub(),
		SourceIP: net.ParseIP("203.0.113.9"), Reason: sensordom.RefusalClockSkew, ClockSkew: 4 * time.Hour})
	v := f.view(a, exp.ID)
	if v.LastRefusal == nil || v.LastRefusal.Reason != sensordom.RefusalClockSkew || v.LastRefusal.ClockOffsetSeconds == nil ||
		*v.LastRefusal.ClockOffsetSeconds != 14400 || v.LastRefusal.SourceIP != "203.0.113.9" {
		t.Fatalf("clock skew refusal: %+v", v.LastRefusal)
	}
	// Another organization never sees it.
	pid, _ := shared.IDFromString(exp.ID)
	if _, err := f.svc.GetExpectation(ctx, b, pid); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	// One sensor attaches; a second key on the same code is refused
	// (uniform answer to it) and the console hears about it, after the
	// throttle.
	first := newSensor(0)
	f.start(first, exp.Code, "")
	second := newSensor(0)
	f.start(second, exp.Code, "")
	if v := f.view(a, exp.ID); v.LastRefusal.Reason != sensordom.RefusalClockSkew {
		t.Fatalf("throttle: a second refusal within seconds was written: %+v", v.LastRefusal)
	}
	f.now = f.now.Add(10 * time.Second)
	third := newSensor(0)
	f.start(third, exp.Code, "")
	v = f.view(a, exp.ID)
	if v.LastRefusal == nil || v.LastRefusal.Reason != sensordom.RefusalCodeTaken || v.LastRefusal.KeyFingerprint == v.KeyFingerprint {
		t.Fatalf("code taken refusal: %+v", v.LastRefusal)
	}
	// A code that matches no expectation writes nothing anywhere.
	f.svc.RecordRefusal(ctx, sensorpairing.Refusal{Code: "AAAA-AAAA", PublicKey: second.pub(), Reason: sensordom.RefusalRateLimited})
	var n int
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_pairings WHERE last_refusal = 'rate_limited'`).Scan(&n)
	if n != 0 {
		t.Fatalf("a refusal on an unknown code was written: %d", n)
	}
}

func TestPairing_UnconfirmedApprovalLeavesNoSensor_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-ghost")
	// Paired and confirmed: kept.
	kept := newSensor(0)
	f.start(kept, "", "")
	f.reveal(kept)
	kid, _ := shared.IDFromString(kept.resp.PairingID)
	if _, err := f.svc.Approve(ctx, a, kid, approve(a, kept.resp.UserCode)); err != nil {
		t.Fatal(err)
	}
	st := f.status(kept)
	if _, err := f.confirm(kept, st.Identity); err != nil {
		t.Fatal(err)
	}
	// Approved while the sensor was stopped: never confirmed.
	ghost := newSensor(0)
	f.start(ghost, "", "")
	f.reveal(ghost)
	gid, _ := shared.IDFromString(ghost.resp.PairingID)
	in := approve(a, ghost.resp.UserCode)
	in.Name = "ghost"
	if _, err := f.svc.Approve(ctx, a, gid, in); err != nil {
		t.Fatal(err)
	}
	ghostID := f.status(ghost).Identity.SensorID
	count := func(id string) int {
		var n int
		_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensors WHERE id = $1`, id).Scan(&n)
		return n
	}
	// Within the confirmation window nothing is removed.
	f.now = f.now.Add(2 * time.Minute)
	exp, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{})
	if err != nil {
		t.Fatal(err)
	}
	if count(ghostID) != 1 {
		t.Fatal("removed inside the confirmation window")
	}
	// After it, the sweep revokes the key and removes the sensor.
	f.now = f.now.Add(sensorpairing.ConfirmWindow)
	_ = f.view(a, exp.ID)
	if count(ghostID) != 0 {
		t.Fatal("an unconfirmed sensor is left behind")
	}
	if count(st.Identity.SensorID) != 1 {
		t.Fatal("a confirmed sensor was removed")
	}
}

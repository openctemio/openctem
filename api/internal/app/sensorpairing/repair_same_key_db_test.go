package sensorpairing_test

// A sensor keeps the key it generated across restarts (its data volume), so
// it may start pairing again before anyone approved it: stopped while it
// waited, or given a new code. The key's unapproved requests give way to
// the new start; an approved key never pairs again, and a code another key
// holds is never taken over.

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// restart is the same sensor process started again: same key, new nonce.
func (s *sensor) restart() {
	s.nonce = make([]byte, 32)
	_, _ = rand.Read(s.nonce)
	s.commitment = pairing.Commit(s.nonce)
	s.resp = nil
}

func (f *fixture) tryStart(s *sensor, code string) error {
	resp, err := f.svc.Start(context.Background(), sensorpairing.StartInput{
		Request: pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(s.pub()),
			Commitment: pairing.Encode(s.commitment), Code: code, Host: pairing.HostFacts{Hostname: "io-sensor"}},
		PublicKey: s.pub(), SourceIP: net.ParseIP("203.0.113.9"),
	})
	if err != nil {
		return err
	}
	if s.platformPub, s.pNonce, err = pairing.VerifyStart(resp, s.pub(), s.commitment, "", sensorsig.Thumbprint); err != nil {
		f.t.Fatalf("platform signature: %v", err)
	}
	s.resp = resp
	return nil
}

func (f *fixture) pairingStatus(id string) string {
	f.t.Helper()
	var st string
	if err := f.db.QueryRowContext(context.Background(), `SELECT status FROM sensor_pairings WHERE id = $1`, id).Scan(&st); err != nil {
		f.t.Fatalf("status of %s: %v", id, err)
	}
	return st
}

func (f *fixture) expect(a sensorpairing.Actor, name string) *sensorpairing.View {
	f.t.Helper()
	v, err := f.svc.Expect(context.Background(), a, sensorpairing.ExpectInput{Name: name})
	if err != nil {
		f.t.Fatalf("expect: %v", err)
	}
	return v
}

// The owner's case: the sensor attached to code A and showed its
// fingerprint, was stopped before approval, and came back with code B.
func TestPairing_SameKeyNewCodeSupersedesUnapproved_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-a")
	expA := f.expect(a, "io-sensor")
	s := newSensor(41)
	f.start(s, expA.Code, "")
	f.reveal(s)

	expB := f.expect(a, "io-sensor")
	s.restart()
	if err := f.tryStart(s, expB.Code); err != nil {
		t.Fatalf("same key with a new code: %v", err)
	}
	if s.resp.PairingID != expB.ID {
		t.Fatalf("attached to %s, want expectation B %s", s.resp.PairingID, expB.ID)
	}
	if st := f.pairingStatus(expA.ID); st != "expired" {
		t.Fatalf("request A after the new start: %s", st)
	}
	aid, _ := shared.IDFromString(expA.ID)
	if _, err := f.svc.Approve(ctx, a, aid, approve(a, "")); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("approve the superseded request: %v", err)
	}
	if _, err := f.svc.Status(ctx, aid, s.thumb()); err != nil {
		t.Fatalf("status of A: %v", err)
	}
	// B pairs normally.
	f.reveal(s)
	bid, _ := shared.IDFromString(expB.ID)
	if _, err := f.svc.Approve(ctx, a, bid, approve(a, "")); err != nil {
		t.Fatalf("approve B: %v", err)
	}
	st := f.status(s)
	if st.Identity == nil || st.Identity.TenantID != a.TenantID.String() {
		t.Fatalf("identity after B: %+v", st)
	}
	if _, err := f.confirm(s, st.Identity); err != nil {
		t.Fatalf("confirm B: %v", err)
	}
}

// A request past its deadline that the sweep has not reached yet still
// holds the key in the database; the new start releases it.
func TestPairing_SameKeyStaleRequestReleased_DB(t *testing.T) {
	f := newFixture(t)
	a := f.org("org-a")
	expA := f.expect(a, "io-sensor")
	s := newSensor(42)
	f.start(s, expA.Code, "")
	f.exec(`UPDATE sensor_pairings SET expires_at = $2 WHERE id = $1`, expA.ID, f.now.Add(-time.Second))
	expB := f.expect(a, "io-sensor")
	s.restart()
	if err := f.tryStart(s, expB.Code); err != nil {
		t.Fatalf("start after a stale request: %v", err)
	}
	if s.resp.PairingID != expB.ID || f.pairingStatus(expA.ID) != "expired" {
		t.Fatalf("stale request not released: %s %s", s.resp.PairingID, f.pairingStatus(expA.ID))
	}
}

// Restarted with the same code: the key's own request is re-armed (same id,
// the admin's expectation), not closed.
func TestPairing_SameKeySameCodeRearms_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-a")
	exp := f.expect(a, "io-sensor")
	s := newSensor(43)
	f.start(s, exp.Code, "")
	f.reveal(s)
	s.restart()
	f.start(s, exp.Code, "")
	if s.resp.PairingID != exp.ID || f.pairingStatus(exp.ID) != "pending" {
		t.Fatalf("re-armed request: %s %s", s.resp.PairingID, f.pairingStatus(exp.ID))
	}
	// The new nonce opens the new commitment (the old reveal was reset).
	f.reveal(s)
	id, _ := shared.IDFromString(exp.ID)
	if _, err := f.svc.Approve(ctx, a, id, approve(a, "")); err != nil {
		t.Fatalf("approve the re-armed request: %v", err)
	}
	if st := f.status(s); st.Identity == nil {
		t.Fatalf("identity: %+v", st)
	}
}

// Without a code: the restart gets a new user code; the old one is dead.
func TestPairing_SameKeyCodelessRestart_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-a")
	s := newSensor(44)
	f.start(s, "", "")
	f.reveal(s)
	oldCode, oldID := s.resp.UserCode, s.resp.PairingID
	s.restart()
	f.start(s, "", "")
	if s.resp.UserCode == "" || s.resp.UserCode == oldCode || s.resp.PairingID == oldID {
		t.Fatalf("codeless restart: %+v", s.resp)
	}
	if _, err := f.svc.Lookup(ctx, a, oldCode); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("the superseded code is still found: %v", err)
	}
	f.reveal(s)
	if v, err := f.svc.Lookup(ctx, a, s.resp.UserCode); err != nil || v.SAS != s.sas() {
		t.Fatalf("lookup of the new code: %v", err)
	}
}

// An approved key never pairs again: not with a new code of its
// organization, not into another organization, not after it completed. The
// other organization's code is left untouched.
func TestPairing_ApprovedKeyRefused_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.org("org-a"), f.org("org-b")
	s := newSensor(45)
	f.start(s, "", "")
	f.reveal(s)
	id, _ := shared.IDFromString(s.resp.PairingID)
	if _, err := f.svc.Approve(ctx, a, id, approve(a, s.resp.UserCode)); err != nil {
		t.Fatal(err)
	}
	approvedID, approvedResp := s.resp.PairingID, s.resp
	st := f.status(s)

	// Approved, not confirmed yet.
	expA := f.expect(a, "again")
	s.restart()
	if err := f.tryStart(s, expA.Code); !errors.Is(err, sensorpairing.ErrKeyRegistered) {
		t.Fatalf("approved key, same organization: %v", err)
	}
	expB := f.expect(b, "foreign")
	if err := f.tryStart(s, expB.Code); !errors.Is(err, sensorpairing.ErrKeyRegistered) {
		t.Fatalf("approved key into another organization: %v", err)
	}
	if err := f.tryStart(s, ""); !errors.Is(err, sensorpairing.ErrKeyRegistered) {
		t.Fatalf("approved key, codeless: %v", err)
	}
	if f.pairingStatus(expB.ID) != "expecting" || f.pairingStatus(expA.ID) != "expecting" || f.pairingStatus(approvedID) != "approved" {
		t.Fatalf("a refused start changed a request: A %s B %s approved %s",
			f.pairingStatus(expA.ID), f.pairingStatus(expB.ID), f.pairingStatus(approvedID))
	}

	// Completed.
	s.resp = approvedResp
	if _, err := f.confirm(s, st.Identity); err != nil {
		t.Fatal(err)
	}
	s.restart()
	if err := f.tryStart(s, expB.Code); !errors.Is(err, sensorpairing.ErrKeyRegistered) {
		t.Fatalf("completed key into another organization: %v", err)
	}
	if f.pairingStatus(expB.ID) != "expecting" {
		t.Fatal("organization B's code was touched")
	}
}

// A code another key holds is never taken over: the second key gets the
// uniform answer (a request no code reaches) and the first sensor's request
// stays approvable.
func TestPairing_CodeHeldByAnotherKeyRefused_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-a")
	exp := f.expect(a, "io-sensor")
	owner := newSensor(46)
	f.start(owner, exp.Code, "")
	f.reveal(owner)

	thief := newSensor(47)
	if err := f.tryStart(thief, exp.Code); err != nil {
		t.Fatalf("start with a held code: %v", err)
	}
	if thief.resp.PairingID == exp.ID || thief.resp.UserCode != "" {
		t.Fatalf("the second key reached the held code: %+v", thief.resp)
	}
	var thumb string
	_ = f.db.QueryRowContext(ctx, `SELECT thumbprint FROM sensor_pairings WHERE id = $1`, exp.ID).Scan(&thumb)
	if thumb != owner.thumb() || f.pairingStatus(exp.ID) != "pending" {
		t.Fatalf("the held request changed: %s %s", thumb, f.pairingStatus(exp.ID))
	}
	id, _ := shared.IDFromString(exp.ID)
	if _, err := f.svc.Approve(ctx, a, id, approve(a, "")); err != nil {
		t.Fatalf("approve the legitimate sensor: %v", err)
	}
	if st := f.status(owner); st.Identity == nil {
		t.Fatalf("legitimate sensor identity: %+v", st)
	}
}

// An unapproved key may move to another organization's code (nothing was
// bound yet); the first organization can no longer approve it, and cannot
// see the second organization's request.
func TestPairing_UnapprovedKeyMovesOrganization_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.org("org-a"), f.org("org-b")
	expA := f.expect(a, "io-sensor")
	s := newSensor(48)
	f.start(s, expA.Code, "")
	f.reveal(s)
	expB := f.expect(b, "io-sensor")
	s.restart()
	f.start(s, expB.Code, "")
	f.reveal(s)
	aid, _ := shared.IDFromString(expA.ID)
	if _, err := f.svc.Approve(ctx, a, aid, approve(a, "")); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("organization A approved a superseded request: %v", err)
	}
	bid, _ := shared.IDFromString(expB.ID)
	if _, err := f.svc.GetExpectation(ctx, a, bid); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("organization A read B's request: %v", err)
	}
	if _, err := f.svc.Approve(ctx, a, bid, approve(a, "")); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("organization A approved B's request: %v", err)
	}
	if _, err := f.svc.Approve(ctx, b, bid, approve(b, "")); err != nil {
		t.Fatalf("organization B approves: %v", err)
	}
	if st := f.status(s); st.Identity == nil || st.Identity.TenantID != b.TenantID.String() {
		t.Fatalf("identity: %+v", st)
	}
}

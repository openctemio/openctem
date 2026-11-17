package sensorpairing_test

// A pairing code belongs to the organization that made it and is good for
// one sensor, once, until it expires
// (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §4.4 and §4.9,
// threat 36). Install snippets keep the code after it is spent, so a sensor
// restarted from one presents it again: such a start pairs under a new code
// printed on the host only, and the old code finds nothing in any
// organization.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/sensorpairing"
	"github.com/openctemio/openctem/server/pkg/sensorproto/pairing"
)

const actionPairingCodeRefused = "sensor.pairing_code_refused"

func TestPairing_StaleCodeIsNeverApprovable_DB(t *testing.T) {
	ctx := context.Background()

	// refused asserts that code finds nothing for anybody: neither the
	// organization that made it nor another one can look it up or approve
	// the request the stale start opened with it.
	refused := func(t *testing.T, f *fixture, s *sensor, code string, orgs ...sensorpairing.Actor) {
		t.Helper()
		if s.resp.UserCode == "" || s.resp.PairingID == "" {
			t.Fatalf("a stale start must still get a request (with a new code): %+v", s.resp)
		}
		f.reveal(s)
		for _, o := range orgs {
			if _, err := f.svc.Lookup(ctx, o, code); !errors.Is(err, sensorpairing.ErrNotFound) {
				t.Errorf("an organization found a request by a stale code: %v", err)
			}
			if _, err := f.approveP(ctx, o, mustID(t, s.resp.PairingID), approve(o, code)); !errors.Is(err, sensorpairing.ErrNotFound) {
				t.Fatalf("an organization approved a request with a stale code: %v", err)
			}
		}
		if st := f.pairingStatus(s.resp.PairingID); st != "pending" {
			t.Fatalf("the request was closed by the refused attempts: %s", st)
		}
		if s.resp.UserCode == code {
			t.Fatalf("a stale code was kept as the request's own code: %+v", s.resp)
		}
	}

	t.Run("expired code, another organization", func(t *testing.T) {
		f := newFixture(t)
		f.withTenantsAndAudit()
		a, b := f.org("org-a"), f.org("org-b")
		f.cleanAudit(a.TenantID, b.TenantID)
		exp := f.expect(a, "dmz-01")
		f.now = f.now.Add(pairing.TTL + time.Minute)
		s := newSensor(91)
		f.start(s, exp.Code, "")
		refused(t, f, s, exp.Code, b, a)
		if f.pairingStatus(exp.ID) != "expired" {
			t.Fatalf("the expired expectation stays open: %s", f.pairingStatus(exp.ID))
		}
		// The organization that made the code hears that a sensor tried it.
		if n := f.auditCount(a.TenantID, actionPairingCodeRefused); n != 1 {
			t.Fatalf("stale code audit in the organization that made it: %d", n)
		}
		if n := f.auditCount(b.TenantID, actionPairingCodeRefused); n != 0 {
			t.Fatalf("stale code audited in another organization: %d", n)
		}
		// The host's own new code is the one that pairs (the codeless flow).
		f.now = time.Now().Add(pairing.TTL + 2*time.Minute)
		if v, err := f.svc.Lookup(ctx, a, s.resp.UserCode); err != nil || v.ID != s.resp.PairingID {
			t.Fatalf("lookup by the host's new code: %v %+v", err, v)
		}
		if _, err := f.approveP(ctx, a, mustID(t, s.resp.PairingID), approve(a, s.resp.UserCode)); err != nil {
			t.Fatalf("approve by the host's new code: %v", err)
		}
	})

	t.Run("used code replayed by a new key", func(t *testing.T) {
		f := newFixture(t)
		f.withTenantsAndAudit()
		a, b := f.org("org-a"), f.org("org-b")
		f.cleanAudit(a.TenantID, b.TenantID)
		eid, first := f.expected(a, "used-01")
		code := first.resp.UserCode // the expectation's code
		if _, err := f.approveP(ctx, a, eid, approve(a, "")); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if st := f.status(first); st.Identity == nil {
			t.Fatalf("approved without identity: %+v", st)
		} else if _, err := f.confirm(first, st.Identity); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		replay := newSensor(92)
		f.start(replay, code, "")
		refused(t, f, replay, code, b, a)
		if f.auditCount(a.TenantID, actionPairingCodeRefused) != 1 {
			t.Fatal("a replayed used code was not audited in its organization")
		}
	})

	t.Run("denied code replayed", func(t *testing.T) {
		f := newFixture(t)
		a, b := f.org("org-a"), f.org("org-b")
		exp := f.expect(a, "denied-01")
		s := newSensor(93)
		f.start(s, exp.Code, "")
		f.reveal(s)
		if err := f.svc.Deny(ctx, a, mustID(t, exp.ID), exp.Code); err != nil {
			t.Fatalf("deny: %v", err)
		}
		again := newSensor(94)
		f.start(again, exp.Code, "")
		refused(t, f, again, exp.Code, b, a)
	})

	t.Run("a code nobody made", func(t *testing.T) {
		f := newFixture(t)
		a, b := f.org("org-a"), f.org("org-b")
		s := newSensor(95)
		f.start(s, "ZZZZ-ZZZZ", "")
		refused(t, f, s, "ZZZZ-ZZZZ", a, b)
		// A restart of the same key with the same code opens a new request
		// (new code) and closes its earlier one.
		first := s.resp.PairingID
		s.restart()
		f.start(s, "ZZZZ-ZZZZ", "")
		if s.resp.PairingID == first || s.resp.UserCode == "ZZZZ-ZZZZ" {
			t.Fatalf("restart with an unknown code: %+v", s.resp)
		}
		if f.pairingStatus(first) != "expired" {
			t.Fatalf("the earlier request of the key stays open: %s", f.pairingStatus(first))
		}
	})

	t.Run("an open code still attaches, only in its organization", func(t *testing.T) {
		f := newFixture(t)
		a, b := f.org("org-a"), f.org("org-b")
		exp := f.expect(a, "open-01")
		s := newSensor(96)
		f.start(s, exp.Code, "")
		if s.resp.UserCode != exp.Code || s.resp.PairingID != exp.ID {
			t.Fatalf("an open code must attach: %+v", s.resp)
		}
		f.reveal(s)
		if _, err := f.svc.Lookup(ctx, b, exp.Code); !errors.Is(err, sensorpairing.ErrNotFound) {
			t.Fatalf("another organization found an open code: %v", err)
		}
		// The same key restarted with the same open code re-arms its request.
		s.restart()
		f.start(s, exp.Code, "")
		if s.resp.PairingID != exp.ID || s.resp.UserCode != exp.Code {
			t.Fatalf("restart with the open code: %+v", s.resp)
		}
		// Another key with the held code gets its own request under a new
		// code, never the held one (threat 28).
		other := newSensor(97)
		f.start(other, exp.Code, "")
		refused(t, f, other, exp.Code, b)
		f.reveal(s)
		if _, err := f.approveP(ctx, a, mustID(t, exp.ID), approve(a, exp.Code)); err != nil {
			t.Fatalf("approve the open code in its organization: %v", err)
		}
	})
}

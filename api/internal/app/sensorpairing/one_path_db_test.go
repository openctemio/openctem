package sensorpairing_test

// One install path (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §4.2 and §4.5, threats 26-29): a start with a code uses that code as its
// own, so the console command, the sensor's output and the approval link
// show one code; the sensor gets the page to approve it on; the approver
// picks the fingerprint the host shows out of three, and a wrong pick
// closes the request.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
)

func TestPairing_OneCodeEverywhere_DB(t *testing.T) {
	f := newFixture(t)
	f.svc.SetVerificationURL("https://ctem.example.com/")
	ctx := context.Background()
	a, b := f.org("org-a"), f.org("org-b")

	// The console's code is the sensor's code and the link's code.
	exp := f.expect(a, "dmz-01")
	s := newSensor(81)
	f.start(s, exp.Code, "")
	if s.resp.UserCode != exp.Code || s.resp.PairingID != exp.ID {
		t.Fatalf("start with the console's code: %+v", s.resp)
	}
	if s.resp.VerificationURI != "https://ctem.example.com/activate" ||
		s.resp.VerificationURIComplete != "https://ctem.example.com/activate?code="+exp.Code {
		t.Fatalf("verification links: %q %q", s.resp.VerificationURI, s.resp.VerificationURIComplete)
	}
	f.reveal(s)
	// The link's lookup finds it in the organization that made the code,
	// and nowhere else (threat 29).
	if v, err := f.svc.Lookup(ctx, a, exp.Code); err != nil || v.ID != exp.ID || v.SAS != s.sas() {
		t.Fatalf("lookup of an attached request in its organization: %v %+v", err, v)
	}
	if _, err := f.svc.Lookup(ctx, b, exp.Code); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("another organization found an attached request: %v", err)
	}
	if _, err := f.approveP(ctx, b, mustID(t, exp.ID), approve(b, exp.Code)); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("another organization approved an attached request: %v", err)
	}
	if _, err := f.approveP(ctx, a, mustID(t, exp.ID), approve(a, exp.Code)); err != nil {
		t.Fatalf("approve from the link: %v", err)
	}

	// The command was run after its code expired: the code becomes the
	// request's own; nothing silently changes the code the person sees.
	late := f.expect(a, "late-01")
	f.now = f.now.Add(pairing.TTL + time.Minute)
	l := newSensor(82)
	f.start(l, late.Code, "")
	if l.resp.UserCode != late.Code || l.resp.PairingID == late.ID {
		t.Fatalf("start with an expired console code: %+v", l.resp)
	}
	if f.pairingStatus(late.ID) != "expired" {
		t.Fatalf("the stale expectation stays open: %s", f.pairingStatus(late.ID))
	}
	f.reveal(l)
	if v, err := f.svc.Lookup(ctx, a, late.Code); err != nil || v.ID != l.resp.PairingID {
		t.Fatalf("lookup of a late start: %v %+v", err, v)
	}
	f.now = time.Now()

	// A start without a code prints a fresh code and the links.
	n := newSensor(83)
	f.start(n, "", "")
	if n.resp.UserCode == "" || !strings.HasSuffix(n.resp.VerificationURIComplete, "?code="+n.resp.UserCode) {
		t.Fatalf("codeless start: %+v", n.resp)
	}

	// A restarted sensor with the same code keeps the same code.
	r := newSensor(84)
	f.start(r, "R5T7-K2M9", "")
	first := r.resp.PairingID
	r.restart()
	f.start(r, "R5T7-K2M9", "")
	if r.resp.UserCode != "R5T7-K2M9" || r.resp.PairingID == first {
		t.Fatalf("restart with the same code: %+v", r.resp)
	}
	if f.pairingStatus(first) != "expired" {
		t.Fatalf("the earlier request of the key stays open: %s", f.pairingStatus(first))
	}
}

func TestPairing_VerificationURLNeedsAnHTTPOrigin_DB(t *testing.T) {
	f := newFixture(t)
	for _, origin := range []string{"", "ctem.example.com", "javascript:alert(1)", "ftp://x"} {
		f.svc.SetVerificationURL(origin)
		s := newSensor(85)
		f.start(s, "", "")
		if s.resp.VerificationURI != "" || s.resp.VerificationURIComplete != "" {
			t.Fatalf("origin %q gave a link: %+v", origin, s.resp)
		}
	}
}

func TestPairing_ApproverPicksTheHostFingerprint_DB(t *testing.T) {
	f := newFixture(t)
	f.withTenantsAndAudit()
	ctx := context.Background()
	a := f.org("org-a")
	f.cleanAudit(a.TenantID)

	s := newSensor(86)
	f.start(s, "", "")
	f.reveal(s)
	id := mustID(t, s.resp.PairingID)
	v, err := f.svc.Lookup(ctx, a, s.resp.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	// Three distinct choices, the host's among them, the same on a reload.
	if len(v.FingerprintChoices) != 3 {
		t.Fatalf("choices: %v", v.FingerprintChoices)
	}
	seen, decoys := map[string]bool{}, []string{}
	for _, c := range v.FingerprintChoices {
		if seen[c] {
			t.Fatalf("duplicate choice: %v", v.FingerprintChoices)
		}
		seen[c] = true
		if c != s.sas() {
			decoys = append(decoys, c)
		}
	}
	if !seen[s.sas()] || len(decoys) != 2 {
		t.Fatalf("the host's fingerprint is not offered once: %v (host %q)", v.FingerprintChoices, s.sas())
	}
	again, _ := f.svc.Lookup(ctx, a, s.resp.UserCode)
	if strings.Join(again.FingerprintChoices, "|") != strings.Join(v.FingerprintChoices, "|") {
		t.Fatalf("choices change on a reload: %v vs %v", v.FingerprintChoices, again.FingerprintChoices)
	}
	// Each decoy differs from the host's in the number and every word.
	hostParts := strings.Split(s.sas(), " · ")
	for _, d := range decoys {
		parts := strings.Split(d, " · ")
		for i := range parts {
			if parts[i] == hostParts[i] {
				t.Fatalf("decoy %q shares part %d with %q", d, i, s.sas())
			}
		}
	}

	// No pick: refused before anything else.
	in := approve(a, s.resp.UserCode)
	in.Fingerprint = "  "
	if _, err := f.approveP(ctx, a, id, in); !errors.Is(err, sensorpairing.ErrFingerprintRequired) {
		t.Fatalf("approve without a pick: %v", err)
	}
	// A wrong pick without the second factor closes nothing.
	f.stepUp.ok = false
	in = approve(a, s.resp.UserCode)
	in.Fingerprint = decoys[0]
	if _, err := f.approveP(ctx, a, id, in); !errors.Is(err, authapp.ErrStepUpFailed) {
		t.Fatalf("wrong pick with a failed step-up: %v", err)
	}
	if f.pairingStatus(s.resp.PairingID) != "pending" {
		t.Fatal("a request was closed without the second factor")
	}
	f.stepUp.ok = true

	// A wrong pick closes the request, audits it high, and the sensor
	// learns it was refused.
	if _, err := f.approveP(ctx, a, id, in); !errors.Is(err, sensorpairing.ErrFingerprintMismatch) {
		t.Fatalf("wrong pick: %v", err)
	}
	if f.pairingStatus(s.resp.PairingID) != "denied" {
		t.Fatalf("after a wrong pick: %s", f.pairingStatus(s.resp.PairingID))
	}
	if st := f.status(s); st.Status != pairing.StatusDenied {
		t.Fatalf("sensor status after a wrong pick: %q", st.Status)
	}
	var sev string
	if err := f.db.QueryRowContext(ctx, `SELECT severity FROM audit_logs WHERE tenant_id = $1 AND action = $2 AND result = 'failure'`,
		a.TenantID.String(), string(auditdom.ActionSensorPairingDenied)).Scan(&sev); err != nil || sev != string(auditdom.SeverityHigh) {
		t.Fatalf("wrong pick audit: %v %q", err, sev)
	}
	// The right pick on a closed request changes nothing.
	if _, err := f.approveP(ctx, a, id, approve(a, s.resp.UserCode)); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("approve after the close: %v", err)
	}

	// The right pick, rendered with other spacing and case, approves.
	ok := newSensor(87)
	f.start(ok, "", "")
	f.reveal(ok)
	in = approve(a, ok.resp.UserCode)
	in.Fingerprint = strings.ToUpper(strings.ReplaceAll(ok.sas(), " · ", "  "))
	if _, err := f.approveP(ctx, a, mustID(t, ok.resp.PairingID), in); err != nil {
		t.Fatalf("approve with the host's fingerprint: %v", err)
	}
}

func mustID(t *testing.T, s string) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

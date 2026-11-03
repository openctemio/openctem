package feedrelay

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/transfer/bundle"

	"github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	dom "github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

func (f *fixture) withNotifier() *consolesettingtest.Notifier {
	n := &consolesettingtest.Notifier{}
	f.svc.SetNotifier(n)
	return n
}

// at moves the clock and runs one controller tick.
func (f *fixture) at(t *testing.T, d time.Duration) {
	t.Helper()
	f.now = f.now.Add(d)
	if _, err := f.svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func openKeys(t *testing.T, svc *Service) []string {
	t.Helper()
	open, err := svc.OpenAlerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(open))
	for k := range open {
		out = append(out, k)
	}
	return out
}

// Losing every relay sensor does not go unnoticed: one critical alert
// after an hour, not repeated on later ticks or by another replica that
// takes the lease, and one "resolved" notice when a relay is back.
func TestAlertRelayOffline(t *testing.T) {
	f := newFixture(t)
	n := f.withNotifier()
	f.relayOn(t)
	f.at(t, 30*time.Minute)
	if n.Count() != 0 {
		t.Fatalf("alert inside the grace: %v", n.Subjects)
	}
	f.at(t, 31*time.Minute) // sensor last seen 61 minutes ago
	if n.Count() != 1 || !strings.HasPrefix(n.Subjects[0], "[CRITICAL] Feed relay: no relay sensor online") {
		t.Fatalf("offline alert: %v", n.Subjects)
	}
	if !strings.Contains(n.Bodies[0], "switch feed delivery to direct, or load an offline feed bundle") {
		t.Fatalf("no escape hatch in the alert: %s", n.Bodies[0])
	}
	f.at(t, 5*time.Minute)
	other := f.newService(t, t.TempDir()) // the lease moved to another replica
	other.SetNotifier(n)
	f.now = f.now.Add(2 * time.Minute)
	if _, err := other.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.Count() != 1 {
		t.Fatalf("alert repeated: %v", n.Subjects)
	}
	seen := f.now
	f.relay.LastSeenAt = &seen
	f.at(t, 2*time.Minute)
	if n.Count() != 2 || n.Subjects[1] != "Feed relay: resolved: no relay sensor online" {
		t.Fatalf("resolved notice: %v", n.Subjects)
	}
	if keys := openKeys(t, f.svc); len(keys) != 0 {
		t.Fatalf("still open: %v", keys)
	}
}

// Relay mode chosen at install: the bundled sensor never enrolling is the
// same "no relay" condition, named as such.
func TestAlertBootstrapNeverEnrolled(t *testing.T) {
	f := newFixture(t)
	n := f.withNotifier()
	if _, err := SeedRelayMode(context.Background(), f.settings, mustID(t, "6f1c2a7e-0000-4000-8000-000000000001")); err != nil {
		t.Fatal(err)
	}
	f.now = time.Now() // the seed is stamped with the wall clock
	f.svc = f.newService(t, t.TempDir())
	f.svc.SetNotifier(n)
	f.at(t, 61*time.Minute)
	if n.Count() != 1 || !strings.Contains(n.Bodies[0], "bundled sensor has not enrolled") {
		t.Fatalf("bootstrap alert: %v %v", n.Subjects, n.Bodies)
	}
}

// A feed older than its alert age alerts once; the release feed (issued
// per release) has no age alert.
func TestAlertFeedStale(t *testing.T) {
	f := newFixture(t)
	n := f.withNotifier()
	f.relayOn(t)
	f.at(t, 46*time.Hour) // published tNow-1h: 47h old
	for _, s := range n.Subjects {
		if strings.Contains(s, "out of date") {
			t.Fatalf("stale too early: %v", n.Subjects)
		}
	}
	f.at(t, 2*time.Hour)
	found := false
	for _, k := range openKeys(t, f.svc) {
		found = found || k == AlertConditionStale+":"+dom.FeedVulnFeed
	}
	if !found {
		t.Fatalf("no stale alert: %v", openKeys(t, f.svc))
	}
}

// A cycle that failed verification alerts at once (critical, possible
// tampering) and resolves when a later cycle imports; the failure stays
// one alert while the feed keeps failing.
func TestAlertVerifyFailed(t *testing.T) {
	f := newFixture(t)
	n := f.withNotifier()
	ctx := context.Background()
	f.relayOn(t)
	f.tick(t)
	f.deliver(t, f.relay, f.svc, nil)
	f.feed.planErr = fmt.Errorf("key set: %w: bad", bundle.ErrSignature)
	f.at(t, 2*time.Minute)
	if n.Count() != 1 || !strings.HasPrefix(n.Subjects[0], "[CRITICAL] Feed relay: vulnfeed round failed: verify_failed") {
		t.Fatalf("verify alert: %v", n.Subjects)
	}
	if !strings.Contains(n.Bodies[0], "possible tampering") {
		t.Fatalf("body: %s", n.Bodies[0])
	}
	// The next cycle fails the same way: still one alert.
	f.at(t, 11*time.Minute)
	f.deliver(t, f.relay, f.svc, nil)
	f.at(t, 2*time.Minute)
	if n.Count() != 1 {
		t.Fatalf("repeated: %v", n.Subjects)
	}
	// Fixed: the next cycle imports, the alert resolves.
	f.feed.planErr = nil
	f.feed.plan = Plan{Ready: true}
	f.at(t, 11*time.Minute)
	f.deliver(t, f.relay, f.svc, nil)
	f.at(t, 2*time.Minute)
	if last, _ := f.store.Latest(ctx, dom.FeedVulnFeed); last.Phase != dom.PhaseImported {
		t.Fatalf("no import: %+v", last)
	}
	if n.Count() != 2 || !strings.HasPrefix(n.Subjects[1], "Feed relay: resolved: vulnfeed round failed (verify_failed)") {
		t.Fatalf("resolved: %v", n.Subjects)
	}
}

// A signer refusal alerts as a warning with the signer's sanitized reason
// (escaped in the HTML body).
func TestAlertSignerRefused(t *testing.T) {
	f := newFixture(t)
	n := f.withNotifier()
	f.relayOn(t)
	f.tick(t)
	f.signer.refuse = &jobsign.RefusalError{Status: 403, Reason: "feed_relay_origin", Detail: "not in SIGNER_FEED_ORIGINS <b>"}
	_, _, _ = f.svc.Next(context.Background(), f.relay)
	f.at(t, 2*time.Minute)
	if n.Count() != 1 || !strings.HasPrefix(n.Subjects[0], "[WARNING] Feed relay: vulnfeed round failed: signer_refused") {
		t.Fatalf("signer alert: %v", n.Subjects)
	}
	if strings.Contains(n.Bodies[0], "<b>") || !strings.Contains(n.Bodies[0], "SIGNER_FEED_ORIGINS") {
		t.Fatalf("body: %s", n.Bodies[0])
	}
}

// Switching to direct closes the open alerts with a notice that says so;
// nothing alerts in direct mode.
func TestAlertDirectModeResolves(t *testing.T) {
	f := newFixture(t)
	n := f.withNotifier()
	f.relayOn(t)
	f.at(t, 61*time.Minute)
	if n.Count() != 1 {
		t.Fatalf("offline alert: %v", n.Subjects)
	}
	st, _ := f.svc.Get(context.Background())
	if _, err := f.svc.Update(context.Background(), superAdmin(t), ModeDirect, nil, st.Version, "", ""); err != nil {
		t.Fatal(err)
	}
	f.at(t, 2*time.Minute)
	if n.Count() != 2 || !strings.Contains(n.Bodies[1], "receives its feeds directly") {
		t.Fatalf("direct: %v %v", n.Subjects, n.Bodies)
	}
	f.at(t, 72*time.Hour)
	if n.Count() != 2 {
		t.Fatalf("alert in direct mode: %v", n.Subjects)
	}
}

// The console offers only eligible platform sensors and says why the others
// are not offered; an organization's sensor is never listed.
func TestCandidates(t *testing.T) {
	f := newFixture(t)
	f.shared3.Status = "disabled"
	got, err := f.svc.Candidates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, c := range got {
		reasons[c.Sensor.ID.String()] = c.Reason
	}
	if len(got) != 4 {
		t.Fatalf("candidates %d: %v", len(got), reasons)
	}
	if _, ok := reasons[f.org.ID.String()]; ok {
		t.Fatal("an organization's sensor was offered")
	}
	if reasons[f.relay.ID.String()] != "" || reasons[f.shared2.ID.String()] != "" ||
		reasons[f.shared3.ID.String()] != CandidateInactive || reasons[f.noCap.ID.String()] != CandidateNoCapability {
		t.Fatalf("reasons %v", reasons)
	}
}

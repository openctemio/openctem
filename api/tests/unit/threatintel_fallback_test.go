package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/internal/app/threatsource"
)

type fixedPolicy struct {
	p   threatsource.Policy
	err error
}

func (f fixedPolicy) Policy(context.Context) (threatsource.Policy, error) { return f.p, f.err }

func setBundleFetched(t *testing.T, repo *threatIntelMockRepo, source string, at time.Time) {
	t.Helper()
	st := threatIntelAddSyncStatus(repo, source, true)
	meta := st.Metadata()
	meta[threat.MetaBundleFetched] = at.UTC().Format(time.RFC3339)
	st.SetMetadata(meta)
}

func TestShouldFetchDirect(t *testing.T) {
	now := time.Now().UTC()
	ctx := context.Background()
	type tc struct {
		name    string
		policy  fixedPolicy
		source  string
		fetched time.Duration // age of the bundle copy; 0 = never read
		want    bool
		reason  string
	}
	cases := []tc{
		{"default: direct is the supplier", fixedPolicy{p: threatsource.Policy{DirectAllowed: true}}, "kev", time.Minute, true, threat.ReasonDirectPreferred},
		{"direct off beats everything", fixedPolicy{p: threatsource.Policy{PreferBundle: true}}, "kev", 40 * time.Hour, false, threat.ReasonDirectOff},
		{"direct off, direct preferred", fixedPolicy{}, "epss", 0, false, threat.ReasonDirectOff},
		{"bundle preferred, KEV fresh", fixedPolicy{p: threatsource.Policy{PreferBundle: true, DirectAllowed: true}}, "kev", 5 * time.Hour, false, threat.ReasonBundleFresh},
		{"bundle preferred, KEV stale after 6h", fixedPolicy{p: threatsource.Policy{PreferBundle: true, DirectAllowed: true}}, "kev", 7 * time.Hour, true, threat.ReasonBundleStale},
		{"bundle preferred, EPSS fresh at 40h", fixedPolicy{p: threatsource.Policy{PreferBundle: true, DirectAllowed: true}}, "epss", 40 * time.Hour, false, threat.ReasonBundleFresh},
		{"bundle preferred, EPSS stale after 48h", fixedPolicy{p: threatsource.Policy{PreferBundle: true, DirectAllowed: true}}, "epss", 49 * time.Hour, true, threat.ReasonBundleStale},
		{"bundle preferred, never read", fixedPolicy{p: threatsource.Policy{PreferBundle: true, DirectAllowed: true}}, "kev", 0, true, threat.ReasonBundleMissing},
		{"setting unreadable: as before", fixedPolicy{err: errors.New("db down")}, "kev", time.Minute, true, threat.ReasonDirectPreferred},
	}
	for _, c := range cases {
		repo := newThreatIntelMockRepo()
		if c.fetched > 0 {
			setBundleFetched(t, repo, c.source, now.Add(-c.fetched))
		} else {
			threatIntelAddSyncStatus(repo, c.source, true)
		}
		svc := newThreatIntelService(repo)
		svc.SetSourcePolicy(c.policy)
		got := svc.ShouldFetchDirect(ctx, c.source)
		if got.Run != c.want || got.Reason != c.reason {
			t.Errorf("%s: %+v, want run=%v reason=%s", c.name, got, c.want, c.reason)
		}
	}
	// No setting wired at all: the direct fetch runs.
	repo := newThreatIntelMockRepo()
	if d := newThreatIntelService(repo).ShouldFetchDirect(ctx, "kev"); !d.Run {
		t.Errorf("no policy: %+v", d)
	}
}

// Strict-egress installs: the setting forbids the call, a manual sync
// included, and nothing is stored or marked started.
func TestDirectSyncRefusedWhenOff(t *testing.T) {
	repo := newThreatIntelMockRepo()
	kev := threatIntelAddSyncStatus(repo, "kev", true)
	threatIntelAddSyncStatus(repo, "epss", true)
	svc := newThreatIntelService(repo)
	svc.SetSourcePolicy(fixedPolicy{p: threatsource.Policy{PreferBundle: true}})
	ctx := context.Background()
	if r := svc.SyncKEV(ctx); !errors.Is(r.Error, threat.ErrDirectFetchOff) {
		t.Fatalf("kev: %v", r.Error)
	}
	if r := svc.SyncEPSS(ctx); !errors.Is(r.Error, threat.ErrDirectFetchOff) {
		t.Fatalf("epss: %v", r.Error)
	}
	if kev.LastSyncAt() != nil {
		t.Fatal("a refused sync was marked started")
	}
}

package certmonitor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// memState is an in-memory StateStore.
type memState struct {
	mu sync.Mutex
	m  map[string]map[string]DomainState
}

func newMemState() *memState { return &memState{m: map[string]map[string]DomainState{}} }

func (s *memState) ListStates(_ context.Context, tenantID shared.ID) (map[string]DomainState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]DomainState{}
	for k, v := range s.m[tenantID.String()] {
		out[k] = v
	}
	return out, nil
}

func (s *memState) SaveState(_ context.Context, tenantID shared.ID, st DomainState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[tenantID.String()] == nil {
		s.m[tenantID.String()] = map[string]DomainState{}
	}
	s.m[tenantID.String()][st.Domain] = st
	return nil
}

// ctServer is a fake crt.sh: it records which domains were asked and answers
// with one certificate for "www.<domain>".
type ctServer struct {
	mu     sync.Mutex
	asked  map[string]int
	status func(domain string, n int) int // per-domain status for the n-th ask
}

func (c *ctServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("output") != "json" || q.Get("deduplicate") != "Y" {
			t.Errorf("unexpected crt.sh query %q", r.URL.RawQuery)
		}
		domain := strings.TrimPrefix(q.Get("q"), "%.")
		c.mu.Lock()
		c.asked[domain]++
		n := c.asked[domain]
		c.mu.Unlock()
		if c.status != nil {
			if st := c.status(domain, n); st != http.StatusOK {
				w.WriteHeader(st)
				return
			}
		}
		notAfter := time.Now().UTC().Add(300 * 24 * time.Hour).Format("2006-01-02T15:04:05")
		_, _ = fmt.Fprintf(w, `[{"common_name":"www.%s","name_value":"www.%s","not_after":"%s"}]`, domain, domain, notAfter)
	})
}

func (c *ctServer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.asked {
		n += v
	}
	return n
}

func domainAssets(t *testing.T, tenant shared.ID, n int) []*assetdom.Asset {
	out := make([]*assetdom.Asset, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, mustDomainAsset(t, tenant, fmt.Sprintf("d%03d.example.com", i)))
	}
	return out
}

// RFC-036 P0 acceptance: a tenant with 120 domains gets every domain queried
// within 3 runs at the default cap of 50, and a run right after (an API
// restart) queries nothing.
func TestMonitorTenant_RotatesThroughAllDomains(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}}
	srv := httptest.NewServer(ct.handler(t))
	defer srv.Close()

	svc := NewService(&fakeAssetRepo{assets: domainAssets(t, tenant, 120)}, newFakeExposureRepo(), srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	state := newMemState()
	svc.SetStateStore(state)

	clock := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return clock }

	for run := 1; run <= 3; run++ {
		if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		clock = clock.Add(24 * time.Hour)
	}
	if len(ct.asked) != 120 {
		t.Fatalf("after 3 daily runs %d of 120 domains were queried", len(ct.asked))
	}
	// Run 3 had only 20 never-queried domains left; the other 30 slots went to
	// the oldest successes (run 1's), so 150 queries in total.
	if got := ct.count(); got != 150 {
		t.Errorf("total queries = %d, want 150 (50 per run)", got)
	}
}

// An API restart re-runs the controller at once; domains queried
// successfully within the re-check age are not asked again.
func TestMonitorTenant_RestartDoesNotRequery(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}}
	srv := httptest.NewServer(ct.handler(t))
	defer srv.Close()

	svc := NewService(&fakeAssetRepo{assets: domainAssets(t, tenant, 10)}, newFakeExposureRepo(), srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	svc.SetStateStore(newMemState())
	clock := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return clock }

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if ct.count() != 10 {
		t.Errorf("restart 1 h later re-queried: %d queries for 10 domains", ct.count())
	}
	clock = clock.Add(DefaultRecheckAfter)
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if ct.count() != 20 {
		t.Errorf("next daily run: %d queries, want 20", ct.count())
	}
}

func TestMonitorTenant_RetriesCRTSHThenSucceeds(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}, status: func(_ string, n int) int {
		if n <= 2 {
			return http.StatusBadGateway
		}
		return http.StatusOK
	}}
	srv := httptest.NewServer(ct.handler(t))
	defer srv.Close()

	exp := newFakeExposureRepo()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, exp, srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	state := newMemState()
	svc.SetStateStore(state)

	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil || n != 1 {
		t.Fatalf("want 1 exposure after two 502s, got n=%d err=%v", n, err)
	}
	if ct.asked["example.com"] != 3 {
		t.Errorf("crt.sh asked %d times, want 3", ct.asked["example.com"])
	}
	st := state.m[tenant.String()]["example.com"]
	if st.LastSource != SourceCRTSH || st.LastSuccessAt == nil || st.ConsecutiveFailures != 0 {
		t.Errorf("state after success = %+v", st)
	}
}

func TestMonitorTenant_FallsBackToCertSpotter(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}, status: func(string, int) int { return http.StatusServiceUnavailable }}
	crt := httptest.NewServer(ct.handler(t))
	defer crt.Close()

	var csCalls int
	cs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csCalls++
		q := r.URL.Query()
		if r.URL.Path != "/v1/issuances" || q.Get("domain") != "example.com" || q.Get("include_subdomains") != "true" {
			t.Errorf("unexpected Cert Spotter request %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		if q.Get("after") != "" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		notAfter := time.Now().UTC().Add(5 * 24 * time.Hour).Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, `[{"id":"42","dns_names":["mail.example.com","example.com"],"not_after":%q,"issuer":{"friendly_name":"Let's Encrypt"},"cert_sha256":"ab"}]`, notAfter)
	}))
	defer cs.Close()

	exp := newFakeExposureRepo()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, exp, crt.URL, testLogger())
	svc.setHTTPClient(crt.Client())
	svc.SetCertSpotterFallback(cs.URL)
	state := newMemState()
	svc.SetStateStore(state)

	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	// subdomain_discovered mail.example.com + certificate_expiring for both names.
	if n != 3 {
		t.Fatalf("want 3 exposures from Cert Spotter, got %d", n)
	}
	if ct.asked["example.com"] != crtshAttempts {
		t.Errorf("crt.sh tried %d times before fallback, want %d", ct.asked["example.com"], crtshAttempts)
	}
	if csCalls != 2 {
		t.Errorf("Cert Spotter called %d times, want 2 (one page + the empty page)", csCalls)
	}
	if st := state.m[tenant.String()]["example.com"]; st.LastSource != SourceCertSpotter {
		t.Errorf("last source = %q, want certspotter", st.LastSource)
	}
}

func TestMonitorTenant_BothSourcesFail_BacksOffAndSkips(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}, status: func(string, int) int { return http.StatusBadGateway }}
	crt := httptest.NewServer(ct.handler(t))
	defer crt.Close()
	var csCalls int
	cs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		csCalls++
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer cs.Close()

	assets := []*assetdom.Asset{mustDomainAsset(t, tenant, "a.example.com"), mustDomainAsset(t, tenant, "b.example.com")}
	exp := newFakeExposureRepo()
	svc := NewService(&fakeAssetRepo{assets: assets}, exp, crt.URL, testLogger())
	svc.setHTTPClient(crt.Client())
	svc.SetCertSpotterFallback(cs.URL)
	state := newMemState()
	svc.SetStateStore(state)
	clock := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return clock }

	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil || n != 0 {
		t.Fatalf("both sources down: want n=0 err=nil, got %d %v", n, err)
	}
	// Cert Spotter answered 429 for the first domain; the second never asks it.
	if csCalls != 1 {
		t.Errorf("Cert Spotter called %d times after a 429, want 1", csCalls)
	}
	for _, d := range []string{"a.example.com", "b.example.com"} {
		st := state.m[tenant.String()][d]
		if st.ConsecutiveFailures != 1 || st.NextAttemptAt == nil || !st.NextAttemptAt.Equal(clock.Add(12*time.Hour)) || st.LastError == "" {
			t.Errorf("%s state after failure = %+v", d, st)
		}
	}

	// Six hours later both are still backed off: nothing is queried.
	before := ct.count()
	clock = clock.Add(6 * time.Hour)
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if ct.count() != before {
		t.Errorf("backed-off domains were queried again")
	}

	// The next day they are retried; recovery resets the failure count.
	ct.status = nil
	clock = clock.Add(18 * time.Hour)
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if st := state.m[tenant.String()]["a.example.com"]; st.ConsecutiveFailures != 0 || st.NextAttemptAt != nil || st.LastError != "" {
		t.Errorf("state after recovery = %+v", st)
	}
}

func TestMonitorTenant_NotFoundIsNotRetried(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}, status: func(string, int) int { return http.StatusNotFound }}
	srv := httptest.NewServer(ct.handler(t))
	defer srv.Close()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, newFakeExposureRepo(), srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if ct.asked["example.com"] != 1 {
		t.Errorf("a 404 was retried %d times", ct.asked["example.com"])
	}
}

type fakeVerified struct {
	list []*verifieddomain.VerifiedDomain
}

func (f fakeVerified) ListByTenant(context.Context, shared.ID) ([]*verifieddomain.VerifiedDomain, error) {
	return f.list, nil
}

type fakeTargets struct{ list []*scope.Target }

func (f fakeTargets) ListActive(context.Context, shared.ID) ([]*scope.Target, error) {
	return f.list, nil
}

func TestMonitorTenant_QueriesVerifiedAndScopeDomains(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}}
	srv := httptest.NewServer(ct.handler(t))
	defer srv.Close()

	now := time.Now().UTC()
	verified := verifieddomain.Reconstruct(shared.NewID(), tenant, "acme.io", "tok", verifieddomain.StatusVerified, &now, &now, now, now)
	pending := verifieddomain.Reconstruct(shared.NewID(), tenant, "pending.io", "tok", verifieddomain.StatusPending, nil, nil, now, now)
	mkTarget := func(tt scope.TargetType, pattern string) *scope.Target {
		tg, err := scope.NewTarget(tenant, tt, pattern, "", "")
		if err != nil {
			t.Fatalf("NewTarget(%s %s): %v", tt, pattern, err)
		}
		return tg
	}

	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, newFakeExposureRepo(), srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	svc.SetDomainSources(fakeVerified{list: []*verifieddomain.VerifiedDomain{verified, pending}}, fakeTargets{list: []*scope.Target{
		mkTarget(scope.TargetTypeDomain, "*.scoped.org"),
		mkTarget(scope.TargetTypeDomain, "api.example.com"), // covered by the example.com asset
		mkTarget(scope.TargetTypeCIDR, "10.0.0.0/8"),        // not a domain
		mkTarget(scope.TargetTypeDomain, "corp.local"),      // no public certificates
	}})

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"example.com": true, "acme.io": true, "scoped.org": true}
	if len(ct.asked) != len(want) {
		t.Fatalf("queried %v, want exactly %v", ct.asked, want)
	}
	for d := range ct.asked {
		if !want[d] {
			t.Errorf("unexpected query for %q", d)
		}
	}
}

func TestMergeRoots(t *testing.T) {
	id := shared.NewID()
	got := mergeRoots([]rootDomain{
		{name: "Example.com.", origin: OriginAsset, assetID: &id},
		{name: "www.example.com", origin: OriginScope},
		{name: "shop.example.com", origin: OriginVerified}, // verified under an unverified parent: kept
		{name: "example.com", origin: OriginVerified},      // same name, stronger origin
		{name: "printer.corp.local", origin: OriginAsset},
		{name: "co.uk", origin: OriginScope},
		{name: "x.test", origin: OriginScope},
	})
	if len(got) != 1 || got[0].name != "example.com" || got[0].origin != OriginVerified || got[0].assetID == nil {
		t.Fatalf("mergeRoots = %+v; want only example.com (verified, with its asset)", got)
	}

	got = mergeRoots([]rootDomain{
		{name: "example.com", origin: OriginAsset},
		{name: "shop.example.com", origin: OriginVerified},
	})
	if len(got) != 2 {
		t.Fatalf("verified child under an asset-only parent must stay its own root: %+v", got)
	}
}

func TestFailureBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{0: 0, 1: 12 * time.Hour, 2: 24 * time.Hour, 3: 48 * time.Hour, 5: 7 * 24 * time.Hour, 50: 7 * 24 * time.Hour} {
		if got := failureBackoff(n); got != want {
			t.Errorf("failureBackoff(%d) = %s, want %s", n, got, want)
		}
	}
}

func TestRetryDelay(t *testing.T) {
	if d := retryDelay(1, &statusError{status: 503, retryAfter: 7 * time.Second}); d != 7*time.Second {
		t.Errorf("Retry-After not honored: %s", d)
	}
	if d := retryDelay(1, &statusError{status: 503, retryAfter: time.Hour}); d != maxRetryAfter {
		t.Errorf("Retry-After not capped: %s", d)
	}
	for i := 0; i < 50; i++ {
		d := retryDelay(2, errors.New("x"))
		if d < 2*time.Second || d > 4*time.Second {
			t.Fatalf("attempt 2 delay %s outside [2s,4s]", d)
		}
		if d := retryDelay(10, errors.New("x")); d > retryCap {
			t.Fatalf("delay %s above cap", d)
		}
	}
}

func TestCollectDiscoveries_ExpiredEmitsEvent(t *testing.T) {
	tenant := shared.NewID()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		na := time.Now().UTC().Add(-3 * 24 * time.Hour).Format("2006-01-02T15:04:05")
		_, _ = fmt.Fprintf(w, `[{"common_name":"old.example.com","name_value":"old.example.com","not_after":%q}]`, na)
	}))
	defer srv.Close()
	exp := newFakeExposureRepo()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, exp, srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	var expired int
	for _, e := range exp.byKey {
		if e.EventType() == exposuredom.EventTypeCertificateExpired {
			expired++
			if e.Details()["days_remaining"] != -3 && e.Details()["days_remaining"] != -2 {
				t.Errorf("days_remaining = %v", e.Details()["days_remaining"])
			}
		}
	}
	if expired != 1 {
		t.Errorf("want 1 certificate_expired, got %d", expired)
	}
}

// CT names are untrusted third-party data.
func TestCollectDiscoveries_DropsInvalidHostnames(t *testing.T) {
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	entries := []crtEntry{{NameValue: strings.Join([]string{
		"ok.example.com",
		"<script>alert(1)</script>.example.com",
		"bad\x00null.example.com",
		"-lead.example.com",
		strings.Repeat("a", 64) + ".example.com",
		"under_score.example.com",
		"xn--bcher-kva.example.com",
	}, "\n"), NotAfter: "2027-01-01T00:00:00"}}
	got := collectDiscoveries("example.com", entries, now, defaultExpiryWindow, defaultExpiredLookback, 500).subdomains
	want := []string{"ok.example.com", "under_score.example.com", "xn--bcher-kva.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("subdomains = %v, want %v", got, want)
	}
}

// A sweep stops at its time budget; the domains it did not reach are not
// marked, so they lead the next run.
func TestMonitorTenant_SweepBudget(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}}
	srv := httptest.NewServer(ct.handler(t))
	defer srv.Close()

	svc := NewService(&fakeAssetRepo{assets: domainAssets(t, tenant, 10)}, newFakeExposureRepo(), srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	state := newMemState()
	svc.SetStateStore(state)
	svc.sweepBudget = 3 * time.Minute
	clock := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	// Every clock read advances one minute: the budget runs out after a few domains.
	svc.now = func() time.Time { clock = clock.Add(time.Minute); return clock }

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	n := len(ct.asked)
	if n == 0 || n >= 10 {
		t.Fatalf("budget not applied: %d of 10 domains queried", n)
	}
	if len(state.m[tenant.String()]) != n {
		t.Errorf("unreached domains were marked: %d states for %d queries", len(state.m[tenant.String()]), n)
	}
}

type lockingState struct {
	*memState
	held bool
}

func (l *lockingState) TryLockTenant(context.Context, shared.ID) (func(), bool, error) {
	if l.held {
		return nil, false, nil
	}
	l.held = true
	return func() { l.held = false }, true, nil
}

// Another replica holding the tenant's lock means this one skips the tenant.
func TestMonitorTenant_SkipsWhenTenantLocked(t *testing.T) {
	tenant := shared.NewID()
	ct := &ctServer{asked: map[string]int{}}
	srv := httptest.NewServer(ct.handler(t))
	defer srv.Close()
	svc := NewService(&fakeAssetRepo{assets: domainAssets(t, tenant, 3)}, newFakeExposureRepo(), srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	st := &lockingState{memState: newMemState(), held: true}
	svc.SetStateStore(st)
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if ct.count() != 0 {
		t.Fatalf("queried %d domains while another instance held the lock", ct.count())
	}
	st.held = false
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if ct.count() != 3 || st.held {
		t.Errorf("after the lock was free: %d queries, lock still held=%v", ct.count(), st.held)
	}
}

func TestJitterBounds(t *testing.T) {
	if jitter(0) != 0 || jitter(-time.Second) != 0 {
		t.Fatal("non-positive max must give 0")
	}
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		d := jitter(10 * time.Millisecond)
		if d < 0 || d > 10*time.Millisecond {
			t.Fatalf("jitter %s out of [0,10ms]", d)
		}
		seen[d] = true
	}
	if len(seen) < 10 {
		t.Fatalf("jitter is not spreading: %d distinct values", len(seen))
	}
}

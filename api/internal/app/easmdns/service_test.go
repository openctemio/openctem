package easmdns

import (
	"context"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	"github.com/openctemio/openctem/api/pkg/dnsprobe/dnstest"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memStore mimics the repository: exposures keyed by fingerprint with state.
type memStore struct {
	targets  []Target
	states   map[string]string // asset|kind -> outcome
	exposure map[string]*exposuredom.ExposureEvent
	state    map[string]string // fingerprint -> active/resolved/auto-resolved/accepted
	locked   bool
}

func newMemStore(targets ...Target) *memStore {
	return &memStore{targets: targets, states: map[string]string{}, exposure: map[string]*exposuredom.ExposureEvent{}, state: map[string]string{}}
}

func (m *memStore) DueTargets(context.Context, shared.ID, string, time.Time, int) ([]Target, error) {
	return m.targets, nil
}

func (m *memStore) SaveState(_ context.Context, _, assetID shared.ID, kind, outcome, _ string, _ time.Time) error {
	m.states[assetID.String()+"|"+kind] = outcome
	return nil
}

func (m *memStore) BulkUpsert(_ context.Context, evs []*exposuredom.ExposureEvent) error {
	for _, e := range evs {
		if _, ok := m.state[e.Fingerprint()]; !ok {
			m.state[e.Fingerprint()] = "active" // the upsert never changes an existing state
		}
		m.exposure[e.Fingerprint()] = e
	}
	return nil
}

func (m *memStore) ResolveAuto(_ context.Context, _ shared.ID, _ string, fps []string, _ string) (int, error) {
	n := 0
	for _, fp := range fps {
		if m.state[fp] == "active" {
			m.state[fp] = "auto-resolved"
			n++
		}
	}
	return n, nil
}

func (m *memStore) ReopenAuto(_ context.Context, _ shared.ID, _ string, fps []string, _ string) (int, error) {
	n := 0
	for _, fp := range fps {
		if m.state[fp] == "auto-resolved" {
			m.state[fp] = "active"
			n++
		}
	}
	return n, nil
}

func (m *memStore) TryLockTenant(context.Context, shared.ID, string) (func(), bool, error) {
	if m.locked {
		return nil, false, nil
	}
	return func() {}, true, nil
}

func serviceWith(t *testing.T, zone map[string]dnstest.Entry, store *memStore) (*Service, *dnstest.Server) {
	t.Helper()
	srv, err := dnstest.Start(zone)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	c, _ := dnsprobe.New(dnsprobe.Config{Server: srv.Addr, QPS: 1000})
	return NewService(c, store, store, logger.NewNop()), srv
}

// The life of a dangling record: found → fixed (auto-resolved) → broken again
// (reopened); a resolver failure in between changes nothing; a person's
// acceptance is never reopened.
func TestMonitorTenant_Lifecycle(t *testing.T) {
	tenant := shared.NewID()
	shop := Target{AssetID: shared.NewID(), Name: "shop.acme.example.com"}
	store := newMemStore(shop)
	broken := map[string]dnstest.Entry{
		"shop.acme.example.com": {CNAME: "acme-shop.azurewebsites.net"},
		"azurewebsites.net":     {NS: []string{"ns1.azure.example"}},
	}
	svc, srv := serviceWith(t, broken, store)
	ctx := context.Background()

	res, err := svc.MonitorTenant(ctx, tenant)
	if err != nil || res.Found != 1 {
		t.Fatalf("first run: %+v %v", res, err)
	}
	var fp string
	for k, e := range store.exposure {
		fp = k
		if e.EventType() != exposuredom.EventTypeDanglingCNAME || e.Severity() != exposuredom.SeverityMedium ||
			e.TenantID() != tenant || e.AssetID() == nil || *e.AssetID() != shop.AssetID || e.Source() != Source {
			t.Fatalf("event = %+v", e)
		}
		if e.Details()["provider"] != "Microsoft Azure" || e.Details()["confirmation"] != "pending" {
			t.Fatalf("details = %v", e.Details())
		}
	}

	// Resolver failure: nothing concluded, nothing resolved.
	srv.Set(map[string]dnstest.Entry{"shop.acme.example.com": {RCode: dnsmessage.RCodeServerFailure}})
	res, _ = svc.MonitorTenant(ctx, tenant)
	if res.Unknown != 1 || store.state[fp] != "active" {
		t.Fatalf("servfail run: %+v state=%s", res, store.state[fp])
	}

	// Fixed: the record now resolves.
	srv.Set(map[string]dnstest.Entry{"shop.acme.example.com": {A: []string{"192.0.2.9"}}})
	res, _ = svc.MonitorTenant(ctx, tenant)
	if res.Resolved != 1 || store.state[fp] != "auto-resolved" {
		t.Fatalf("fixed run: %+v state=%s", res, store.state[fp])
	}

	// Broken again: the same exposure reopens (same fingerprint).
	srv.Set(broken)
	res, _ = svc.MonitorTenant(ctx, tenant)
	if res.Reopened != 1 || store.state[fp] != "active" || len(store.exposure) != 1 {
		t.Fatalf("regression run: %+v state=%s rows=%d", res, store.state[fp], len(store.exposure))
	}

	// A person accepts it: later runs neither resolve nor reopen it.
	store.state[fp] = "accepted"
	srv.Set(map[string]dnstest.Entry{"shop.acme.example.com": {A: []string{"192.0.2.9"}}})
	_, _ = svc.MonitorTenant(ctx, tenant)
	srv.Set(broken)
	_, _ = svc.MonitorTenant(ctx, tenant)
	if store.state[fp] != "accepted" {
		t.Fatalf("human acceptance changed to %s", store.state[fp])
	}
}

func TestMonitorTenant_LockedAndBudget(t *testing.T) {
	tenant := shared.NewID()
	store := newMemStore(Target{AssetID: shared.NewID(), Name: "a.example.com"}, Target{AssetID: shared.NewID(), Name: "b.example.com"})
	store.locked = true
	svc, srv := serviceWith(t, map[string]dnstest.Entry{}, store)
	if res, _ := svc.MonitorTenant(context.Background(), tenant); res.Checked != 0 || len(srv.Queries()) != 0 {
		t.Fatalf("checked while another instance holds the lock: %+v", res)
	}
	store.locked = false
	clock := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { clock = clock.Add(20 * time.Minute); return clock }
	if res, _ := svc.MonitorTenant(context.Background(), tenant); res.Checked != 1 {
		t.Fatalf("budget: checked %d, want 1", res.Checked)
	}
}

func TestMonitorEmail_FlagsWeakAndResolvesFixed(t *testing.T) {
	tenant := shared.NewID()
	root := Target{AssetID: shared.NewID(), Name: "acme.com"}
	sub := Target{AssetID: shared.NewID(), Name: "mail.acme.com"} // not registrable: skipped
	store := newMemStore(root, sub)
	svc, srv := serviceWith(t, map[string]dnstest.Entry{"acme.com": {MX: []string{"mx.acme.com"}}}, store)

	res, err := svc.MonitorEmail(context.Background(), tenant)
	if err != nil || res.Found != 1 {
		t.Fatalf("weak run: %+v %v", res, err)
	}
	if store.states[sub.AssetID.String()+"|email"] != "skipped_not_registrable" {
		t.Fatalf("subdomain state = %v", store.states)
	}
	for _, e := range store.exposure {
		if e.EventType() != exposuredom.EventTypeEmailSecurityWeak || e.Severity() != exposuredom.SeverityMedium {
			t.Fatalf("event = %s %s", e.EventType(), e.Severity())
		}
	}
	srv.Set(map[string]dnstest.Entry{
		"acme.com":            {MX: []string{"mx.acme.com"}, TXT: [][]string{{"v=spf1 mx -all"}}},
		"_dmarc.acme.com":     {TXT: [][]string{{"v=DMARC1; p=reject; rua=mailto:d@acme.com"}}},
		"_mta-sts.acme.com":   {TXT: [][]string{{"v=STSv1; id=2"}}},
		"_smtp._tls.acme.com": {TXT: [][]string{{"v=TLSRPTv1; rua=mailto:t@acme.com"}}},
	})
	if res, _ := svc.MonitorEmail(context.Background(), tenant); res.Resolved != 1 {
		t.Fatalf("fixed run: %+v", res)
	}
}

type fakeTenantSettings map[string]tenant.EASMSettings

func (f fakeTenantSettings) GetEASMSettings(_ context.Context, id string) (*tenant.EASMSettings, error) {
	es := f[id]
	return &es, nil
}

// research/22 P0-11 (E3): a tenant that turned the DNS checks off is not
// checked; another tenant is.
func TestMonitor_TenantSwitch(t *testing.T) {
	off, on := shared.NewID(), shared.NewID()
	store := newMemStore(Target{AssetID: shared.NewID(), Name: "acme.com"})
	svc, _ := serviceWith(t, map[string]dnstest.Entry{"acme.com": {MX: []string{"mx.acme.com"}}}, store)
	svc.SetTenantSettings(fakeTenantSettings{off.String(): {DNSChecksDisabled: true}})
	if res, err := svc.MonitorEmail(context.Background(), off); err != nil || res.Checked != 0 {
		t.Fatalf("checked a tenant that turned the checks off: %+v %v", res, err)
	}
	if res, _ := svc.MonitorTenant(context.Background(), off); res.Checked != 0 {
		t.Fatalf("dangling check ran for a tenant with it off: %+v", res)
	}
	if res, err := svc.MonitorEmail(context.Background(), on); err != nil || res.Checked != 1 {
		t.Fatalf("tenant with the checks on: %+v %v", res, err)
	}
}

package certmonitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/ctlookup"

	"github.com/openctemio/openctem/server/internal/app/lookupjob"
	assetdom "github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// fakeSource is a CTSource that records its calls and answers with a canned
// output or error.
type fakeSource struct {
	mu        sync.Mutex
	available bool
	out       ctlookup.Output
	err       error
	tenants   []shared.ID
	domains   []string
}

func (f *fakeSource) Available(context.Context) bool { return f.available }

func (f *fakeSource) Lookup(_ context.Context, tenantID shared.ID, domain string) (ctlookup.Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants = append(f.tenants, tenantID)
	f.domains = append(f.domains, domain)
	return f.out, f.err
}

func (f *fakeSource) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.domains)
}

// okOutput is a crt.sh answer with one record naming names.
func okOutput(notAfter time.Time, names ...string) ctlookup.Output {
	return ctlookup.Output{
		Records: []ctlookup.Record{{
			Source: ctlookup.SourceCRTSH, EntryID: "1", DNSNames: names,
			NotBefore: ctlookup.FormatTime(notAfter.Add(-90 * 24 * time.Hour)), NotAfter: ctlookup.FormatTime(notAfter),
		}},
		SourceStatus: []ctlookup.SourceStatus{{Source: ctlookup.SourceCRTSH, State: ctlookup.StateOK}},
	}
}

func sourceTestService(t *testing.T, tenant shared.ID, domain string, src CTSource) (*Service, *fakeExposureRepo, *memState) {
	t.Helper()
	exp := newFakeExposureRepo()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, domain)}}, exp, testLogger())
	svc.SetSource(src)
	svc.requestDelay, svc.noSleep = 0, true
	state := newMemState()
	svc.SetStateStore(state)
	return svc, exp, state
}

// SECURITY (zero platform egress): without a platform sensor the sweep makes
// no CT request at all, changes no domain's state, and says why.
func TestMonitorTenant_NoPlatformSensorQueriesNothing(t *testing.T) {
	tenant := shared.NewID()
	assetRepo := &fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}
	expRepo := newFakeExposureRepo()
	svc := NewService(assetRepo, expRepo, testLogger())
	state := newMemState()
	svc.SetStateStore(state)
	ctx := context.Background()
	if svc.Available(ctx) || svc.UnavailableReason(ctx) != ReasonNeedsPlatformSensor {
		t.Fatalf("available %t, reason %q", svc.Available(ctx), svc.UnavailableReason(ctx))
	}
	n, err := svc.MonitorTenant(ctx, tenant)
	if err != nil || n != 0 || len(expRepo.byKey) != 0 {
		t.Fatalf("n %d, err %v, exposures %d", n, err, len(expRepo.byKey))
	}
	if st, err := state.ListStates(ctx, tenant); err != nil || len(st) != 0 {
		t.Fatalf("domain state changed: %v %v", st, err)
	}
}

// A source that reports itself unavailable is the same: nothing is asked.
func TestMonitorTenant_UnavailableSourceQueriesNothing(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{available: false, out: okOutput(time.Now().Add(400*24*time.Hour), "www.example.com")}
	svc, exp, state := sourceTestService(t, tenant, "example.com", src)
	ctx := context.Background()
	if svc.Available(ctx) || svc.UnavailableReason(ctx) != ReasonNeedsPlatformSensor {
		t.Fatalf("available %t, reason %q", svc.Available(ctx), svc.UnavailableReason(ctx))
	}
	n, err := svc.MonitorTenant(ctx, tenant)
	if err != nil || n != 0 || len(exp.byKey) != 0 || src.calls() != 0 {
		t.Fatalf("n %d, err %v, exposures %d, lookups %d", n, err, len(exp.byKey), src.calls())
	}
	if st, _ := state.ListStates(ctx, tenant); len(st) != 0 {
		t.Fatalf("domain state changed: %v", st)
	}
	src.available = true
	if !svc.Available(ctx) || svc.UnavailableReason(ctx) != "" {
		t.Fatal("an available source makes CT monitoring available")
	}
}

// exposureText is everything an exposure row says, for "appears nowhere".
func exposureText(rep *fakeExposureRepo) string {
	var b strings.Builder
	for k, e := range rep.byKey {
		d, _ := json.Marshal(e.Details())
		fmt.Fprintf(&b, "%s|%s|%s|%s\n", k, e.Title(), e.Description(), d)
	}
	return b.String()
}

// SECURITY: the platform does not trust the sensor's answer. Names outside
// the queried domain never become exposures or promotions.
func TestMonitorTenant_SensorAnswerIsBoundToTheDomain(t *testing.T) {
	tenant := shared.NewID()
	future := time.Now().UTC().Add(400 * 24 * time.Hour)
	src := &fakeSource{available: true, out: okOutput(future,
		"www.example.com", "victim.example.org", "example.com.evil.test", "*.dev.example.com")}
	svc, exp, _ := sourceTestService(t, tenant, "example.com", src)
	inv := newFakeInventory()
	svc.SetPromotion(inv, inv, newMemAttribution())

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	text := exposureText(exp)
	if !strings.Contains(text, "www.example.com") {
		t.Fatalf("www.example.com missing from exposures:\n%s", text)
	}
	for _, foreign := range []string{"victim.example.org", "example.com.evil.test", "evil.test", "example.org"} {
		if strings.Contains(text, foreign) {
			t.Errorf("foreign name %q reached the exposures:\n%s", foreign, text)
		}
		if _, ok := inv.byName[foreign]; ok {
			t.Errorf("foreign name %q was promoted", foreign)
		}
	}
	for name := range inv.byName {
		if name != "example.com" && !strings.HasSuffix(name, ".example.com") {
			t.Errorf("promoted %q outside example.com", name)
		}
	}
	if _, ok := inv.byName["www.example.com"]; !ok {
		t.Errorf("www.example.com not promoted: %v", inv.byName)
	}
	// A wildcard certificate proves no host: *.dev.example.com keeps its
	// label through the contract and never becomes the host dev.example.com.
	if _, ok := inv.byName["dev.example.com"]; ok || strings.Contains(text, "dev.example.com") {
		t.Errorf("wildcard-only name became a host:\n%s", text)
	}
}

// SECURITY: a lookup is asked for the tenant being swept and its results
// are written under that tenant only.
func TestMonitorTenant_LookupIsBoundToTheTenant(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	src := &fakeSource{available: true, out: okOutput(time.Now().UTC().Add(400*24*time.Hour), "www.example.com")}
	svc, exp, _ := sourceTestService(t, tenantA, "example.com", src)
	// Tenant B's own repository: never touched by tenant A's sweep.
	expB := newFakeExposureRepo()

	n, err := svc.MonitorTenant(context.Background(), tenantA)
	if err != nil || n == 0 {
		t.Fatalf("n %d, err %v", n, err)
	}
	if src.calls() == 0 {
		t.Fatal("no lookup was asked")
	}
	for _, id := range src.tenants {
		if id != tenantA {
			t.Errorf("lookup asked for tenant %s, want %s", id, tenantA)
		}
	}
	for key, e := range exp.byKey {
		if e.TenantID() != tenantA || !strings.HasPrefix(key, tenantA.String()+"|") {
			t.Errorf("exposure written under tenant %s (key %s)", e.TenantID(), key)
		}
		if e.TenantID() == tenantB {
			t.Errorf("exposure leaked to tenant B")
		}
	}
	if len(expB.byKey) != 0 || expB.callCount != 0 {
		t.Errorf("tenant B's repository was touched")
	}
}

// Every source rate-limited or down: the domain backs off, honoring the
// longest retry_after_s; nothing is raised.
func TestMonitorTenant_NoSourceOKBacksOff(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{available: true, out: ctlookup.Output{SourceStatus: []ctlookup.SourceStatus{
		{Source: ctlookup.SourceCRTSH, State: ctlookup.StateRateLimited, RetryAfterS: 7200},
		{Source: ctlookup.SourceCertSpotter, State: ctlookup.StateUnavailable},
	}}}
	svc, exp, state := sourceTestService(t, tenant, "example.com", src)
	clock := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return clock }

	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil || n != 0 || len(exp.byKey) != 0 {
		t.Fatalf("n %d, err %v, exposures %d", n, err, len(exp.byKey))
	}
	st := state.m[tenant.String()]["example.com"]
	if st.ConsecutiveFailures != 1 || st.NextAttemptAt == nil || st.NextAttemptAt.Before(clock.Add(2*time.Hour)) {
		t.Errorf("state = %+v", st)
	}
	if !strings.Contains(st.LastError, "rate_limited") {
		t.Errorf("last error %q does not mention rate_limited", st.LastError)
	}
}

// The sensor going away mid-sweep stops the sweep without marking a domain
// failed.
func TestMonitorTenant_SensorGoneMidSweepStopsWithoutFailure(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{available: true, err: ErrNeedsPlatformSensor}
	svc, exp, state := sourceTestService(t, tenant, "example.com", src)

	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil || n != 0 || len(exp.byKey) != 0 {
		t.Fatalf("n %d, err %v, exposures %d", n, err, len(exp.byKey))
	}
	for d, st := range state.m[tenant.String()] {
		if st.ConsecutiveFailures != 0 || st.NextAttemptAt != nil || st.LastError != "" {
			t.Errorf("%s marked failed: %+v", d, st)
		}
	}
}

// An answer that breaks the contract is a failure of the domain, and none of
// it is used.
func TestMonitorTenant_BrokenAnswerIsAFailure(t *testing.T) {
	tenant := shared.NewID()
	out := okOutput(time.Now().UTC().Add(400*24*time.Hour), "www.example.com")
	out.Records[0].Source = "not-a-source"
	out.SourceStatus[0].Source = "not-a-source"
	src := &fakeSource{available: true, out: out}
	svc, exp, state := sourceTestService(t, tenant, "example.com", src)

	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil || n != 0 || len(exp.byKey) != 0 {
		t.Fatalf("n %d, err %v, exposures %d", n, err, len(exp.byKey))
	}
	st := state.m[tenant.String()]["example.com"]
	if st.ConsecutiveFailures != 1 || st.NextAttemptAt == nil || st.LastError == "" {
		t.Errorf("state = %+v", st)
	}
}

type fakeAsker struct {
	available bool
	raw       []byte
	err       error
	gotCap    string
	gotTarget string
	gotInput  any
	gotTenant shared.ID
}

func (f *fakeAsker) Available(context.Context, string) bool { return f.available }

func (f *fakeAsker) Ask(_ context.Context, tenantID shared.ID, capability, target string, input any) (json.RawMessage, error) {
	f.gotTenant, f.gotCap, f.gotTarget, f.gotInput = tenantID, capability, target, input
	return f.raw, f.err
}

func TestSensorSource_DecodesStrictly(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	good := `{"records":[{"source":"crt.sh","dns_names":["www.example.com"]}],"source_status":[{"source":"crt.sh","state":"ok"}]}`

	a := &fakeAsker{available: true, raw: []byte(good)}
	src := SensorSource{Jobs: a}
	if !src.Available(ctx) || (SensorSource{}).Available(ctx) {
		t.Fatal("Available follows the asker")
	}
	out, err := src.Lookup(ctx, tenant, "example.com")
	if err != nil || len(out.Records) != 1 || out.Records[0].DNSNames[0] != "www.example.com" {
		t.Fatalf("good answer: %+v, %v", out, err)
	}
	if a.gotCap != "lookup.ct@1" || a.gotTarget != "example.com" || a.gotTenant != tenant {
		t.Errorf("asked %q %q tenant %s", a.gotCap, a.gotTarget, a.gotTenant)
	}
	if in, ok := a.gotInput.(ctlookup.Input); !ok || in.Domain != "example.com" {
		t.Errorf("input = %#v", a.gotInput)
	}

	a.raw = []byte(`{"records":[],"source_status":[],"extra":1}`)
	if _, err := src.Lookup(ctx, tenant, "example.com"); !errors.Is(err, errBadAnswer) {
		t.Errorf("unknown field accepted: %v", err)
	}
	a.raw = []byte(`{"records":[],"source_status":[],"pad":"` + strings.Repeat("a", ctlookup.MaxOutputBytes) + `"}`)
	if _, err := src.Lookup(ctx, tenant, "example.com"); !errors.Is(err, errBadAnswer) {
		t.Errorf("oversized answer accepted: %v", err)
	}
	a.raw = []byte(`not json`)
	if _, err := src.Lookup(ctx, tenant, "example.com"); err == nil {
		t.Error("non-JSON accepted")
	}
	a.err = lookupjob.ErrUnavailable
	if _, err := src.Lookup(ctx, tenant, "example.com"); !errors.Is(err, ErrNeedsPlatformSensor) {
		t.Errorf("ErrUnavailable maps to %v", err)
	}
	if _, err := (SensorSource{}).Lookup(ctx, tenant, "example.com"); !errors.Is(err, ErrNeedsPlatformSensor) {
		t.Errorf("no asker: %v", err)
	}
}

// SECURITY (zero platform egress): the package's production code holds no
// HTTP client, dialer or SSRF-guarded client of its own; only tests do.
func TestNoOutboundClientInTheService(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"http.Client", "http.Get(", "http.DefaultClient", "net.Dial", "httpsec.", "tls.Dial"} {
			if strings.Contains(string(src), banned) {
				t.Errorf("%s uses %s: the platform must not reach a CT source itself", f, banned)
			}
		}
	}
}

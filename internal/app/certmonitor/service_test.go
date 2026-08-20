package certmonitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
	exposuredom "github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

func testLogger() *logger.Logger { return logger.NewNop() }

// --- fakes -----------------------------------------------------------------

type fakeAssetRepo struct {
	assets []*assetdom.Asset
}

func (r *fakeAssetRepo) List(_ context.Context, filter assetdom.Filter, _ assetdom.ListOptions, page pagination.Pagination) (pagination.Result[*assetdom.Asset], error) {
	// Only return data on the first page; the sweep pages until empty.
	if page.Page > 1 {
		return pagination.Result[*assetdom.Asset]{Data: nil, Total: int64(len(r.assets))}, nil
	}
	return pagination.Result[*assetdom.Asset]{Data: r.assets, Total: int64(len(r.assets))}, nil
}

// fakeExposureRepo mimics the postgres ON CONFLICT(tenant_id, fingerprint)
// upsert: keyed by (tenant, fingerprint), so re-upserting the same discovery
// leaves the row count unchanged (idempotent dedupe).
type fakeExposureRepo struct {
	byKey     map[string]*exposuredom.ExposureEvent
	callCount int
}

func newFakeExposureRepo() *fakeExposureRepo {
	return &fakeExposureRepo{byKey: make(map[string]*exposuredom.ExposureEvent)}
}

func (r *fakeExposureRepo) BulkUpsert(_ context.Context, events []*exposuredom.ExposureEvent) error {
	r.callCount++
	for _, e := range events {
		r.byKey[e.TenantID().String()+"|"+e.Fingerprint()] = e
	}
	return nil
}

func mustDomainAsset(t *testing.T, tenantID shared.ID, name string) *assetdom.Asset {
	t.Helper()
	a, err := assetdom.NewAssetWithTenant(tenantID, name, assetdom.AssetTypeDomain, assetdom.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAssetWithTenant(%q): %v", name, err)
	}
	return a
}

// --- pure-parse tests ------------------------------------------------------

func TestParseCRTSH_RealShape(t *testing.T) {
	// Real crt.sh shape: bare array, multi-line name_value (SANs), no-tz times.
	body := []byte(`[
	  {"issuer_ca_id":16418,"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"example.com","name_value":"example.com\nwww.example.com","not_before":"2026-06-01T00:00:00","not_after":"2026-09-01T12:00:00","serial_number":"abc123"},
	  {"issuer_ca_id":9,"issuer_name":"DigiCert","common_name":"*.api.example.com","name_value":"*.api.example.com","not_before":"2026-01-01T00:00:00.500000","not_after":"2027-01-01T00:00:00"}
	]`)
	entries, err := parseCRTSH(body)
	if err != nil {
		t.Fatalf("parseCRTSH: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if entries[0].NameValue != "example.com\nwww.example.com" {
		t.Errorf("name_value not preserved: %q", entries[0].NameValue)
	}
	if got := parseCRTTime(entries[0].NotAfter); got.IsZero() {
		t.Errorf("not_after should parse: %q", entries[0].NotAfter)
	}
	if got := parseCRTTime(entries[1].NotBefore); got.IsZero() {
		t.Errorf("fractional-second not_before should parse: %q", entries[1].NotBefore)
	}
}

func TestParseCRTSH_EmptyAndMalformed(t *testing.T) {
	if got, err := parseCRTSH([]byte("  ")); err != nil || got != nil {
		t.Errorf("empty body: got %v, %v", got, err)
	}
	if _, err := parseCRTSH([]byte("<html>rate limited</html>")); err == nil {
		t.Errorf("non-JSON should error")
	}
}

func TestCollectDiscoveries_Subdomains(t *testing.T) {
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	future := "2027-01-01T00:00:00"
	entries := []crtEntry{
		{CommonName: "example.com", NameValue: "example.com\nwww.example.com", NotAfter: future},
		{CommonName: "*.API.example.com", NameValue: "*.api.example.com", NotAfter: future}, // wildcard + case
		{CommonName: "shop.example.com", NameValue: "shop.example.com.", NotAfter: future},  // trailing dot
		{CommonName: "attacker.com", NameValue: "notexample.com", NotAfter: future},         // out of scope
	}
	subs, _ := collectDiscoveries("Example.com", entries, now, defaultExpiryWindow, 500)

	want := map[string]bool{"www.example.com": true, "api.example.com": true, "shop.example.com": true}
	if len(subs) != len(want) {
		t.Fatalf("want %d subdomains, got %d: %v", len(want), len(subs), subs)
	}
	for _, s := range subs {
		if !want[s] {
			t.Errorf("unexpected subdomain %q (apex/out-of-scope should be excluded)", s)
		}
	}
}

func TestCollectDiscoveries_ExpiryUsesNewestCert(t *testing.T) {
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	fmtT := func(tm time.Time) string { return tm.Format("2006-01-02T15:04:05") }

	entries := []crtEntry{
		// host A: an OLD expired cert AND a fresh cert beyond the window -> healthy, NOT expiring.
		{CommonName: "a.example.com", NotAfter: fmtT(now.Add(-100 * 24 * time.Hour))},
		{CommonName: "a.example.com", NotAfter: fmtT(now.Add(200 * 24 * time.Hour)), IssuerName: "LE", SerialNumber: "s-a"},
		// host B: newest cert expires in 5 days -> EXPIRING (high).
		{CommonName: "b.example.com", NotAfter: fmtT(now.Add(-30 * 24 * time.Hour))},
		{CommonName: "b.example.com", NotAfter: fmtT(now.Add(5 * 24 * time.Hour)), IssuerName: "LE", SerialNumber: "s-b"},
		// host C: newest cert already lapsed -> expired, NOT "expiring soon" (dropped).
		{CommonName: "c.example.com", NotAfter: fmtT(now.Add(-1 * 24 * time.Hour))},
	}
	_, expiring := collectDiscoveries("example.com", entries, now, defaultExpiryWindow, 500)

	if len(expiring) != 1 {
		t.Fatalf("want exactly 1 expiring host (b), got %d: %+v", len(expiring), expiring)
	}
	ec := expiring[0]
	if ec.Host != "b.example.com" {
		t.Fatalf("want b.example.com expiring, got %q", ec.Host)
	}
	if ec.DaysLeft < 4 || ec.DaysLeft > 5 {
		t.Errorf("days_left ~5 expected, got %d", ec.DaysLeft)
	}
	if ec.Serial != "s-b" || ec.Issuer != "LE" {
		t.Errorf("issuer/serial taken from newest cert; got %q/%q", ec.Issuer, ec.Serial)
	}
	if sev := expirySeverity(ec.DaysLeft); sev != exposuredom.SeverityHigh {
		t.Errorf("<=7 days should be high, got %s", sev)
	}
}

// --- integration (injected client) -----------------------------------------

func newCRTServer(t *testing.T, payload string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") != "json" {
			t.Errorf("expected output=json, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
}

func TestMonitorTenant_EmitsExposuresAndIsolatesTenant(t *testing.T) {
	tenantA := shared.NewID()
	now := time.Now().UTC()
	expSoon := now.Add(10 * 24 * time.Hour).Format("2006-01-02T15:04:05")
	payload := fmt.Sprintf(`[
	  {"common_name":"example.com","name_value":"example.com\nnew.example.com","not_after":"%s"},
	  {"common_name":"vpn.example.com","name_value":"vpn.example.com","not_after":"%s","issuer_name":"LE","serial_number":"s1"}
	]`, now.Add(400*24*time.Hour).Format("2006-01-02T15:04:05"), expSoon)

	srv := newCRTServer(t, payload)
	defer srv.Close()

	assetRepo := &fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenantA, "example.com")}}
	expRepo := newFakeExposureRepo()

	svc := NewService(assetRepo, expRepo, srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())

	n, err := svc.MonitorTenant(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("MonitorTenant: %v", err)
	}
	// Expect: subdomain_discovered for new.example.com + vpn.example.com,
	// certificate_expiring for vpn.example.com. (apex example.com excluded.)
	if n != 3 {
		t.Fatalf("want 3 exposures, got %d", n)
	}

	var subs, expiring int
	for _, e := range expRepo.byKey {
		if e.TenantID() != tenantA {
			t.Fatalf("tenant isolation: exposure stamped with wrong tenant %s (want %s)", e.TenantID(), tenantA)
		}
		switch e.EventType() {
		case exposuredom.EventTypeSubdomainDiscovered:
			subs++
		case exposuredom.EventTypeCertificateExpiring:
			expiring++
			if e.Severity() != exposuredom.SeverityMedium { // 10 days -> medium
				t.Errorf("10-day expiry should be medium, got %s", e.Severity())
			}
		}
		if e.Source() != Source {
			t.Errorf("source = %q, want %q", e.Source(), Source)
		}
	}
	if subs != 2 || expiring != 1 {
		t.Fatalf("want 2 subdomain + 1 expiring, got %d + %d", subs, expiring)
	}
}

func TestMonitorTenant_IdempotentOnRepoll(t *testing.T) {
	tenant := shared.NewID()
	now := time.Now().UTC()
	payload := fmt.Sprintf(`[
	  {"common_name":"a.example.com","name_value":"a.example.com","not_after":"%s"}
	]`, now.Add(9*24*time.Hour).Format("2006-01-02T15:04:05"))

	srv := newCRTServer(t, payload)
	defer srv.Close()

	assetRepo := &fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}
	expRepo := newFakeExposureRepo()
	svc := NewService(assetRepo, expRepo, srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())

	first, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	second, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if first != second {
		t.Errorf("sweeps should emit same count, got %d then %d", first, second)
	}
	// Same discoveries -> same fingerprints -> no growth in stored rows.
	if len(expRepo.byKey) != first {
		t.Errorf("re-poll must dedupe by fingerprint: %d unique rows for %d emitted", len(expRepo.byKey), first)
	}
}

func TestMonitorTenant_NoDomainsIsInert(t *testing.T) {
	svc := NewService(&fakeAssetRepo{}, newFakeExposureRepo(), "https://crt.sh", testLogger())
	n, err := svc.MonitorTenant(context.Background(), shared.NewID())
	if err != nil || n != 0 {
		t.Fatalf("no domains -> inert; got n=%d err=%v", n, err)
	}
}

// --- SSRF guard on the outbound query --------------------------------------

func TestQueryCRTSH_SSRFGuardBlocksInternal(t *testing.T) {
	// Production path: the default SafeHTTPClient must refuse an internal target
	// even though the feed URL is operator-configurable (DNS-rebinding defense).
	// "localhost" is hard-blocked regardless of the allow-private policy, so this
	// is deterministic and offline.
	svc := NewService(&fakeAssetRepo{}, newFakeExposureRepo(), "http://localhost:9", testLogger())
	if _, err := svc.queryCRTSH(context.Background(), "example.com"); err == nil {
		t.Fatalf("SSRF guard should have blocked an internal/localhost feed target")
	}
}

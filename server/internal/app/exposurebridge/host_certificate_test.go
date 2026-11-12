package exposurebridge_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/exposurebridge"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeResolver resolves the repo's open exposures by fingerprint, as
// EASMDNSRepository.ResolveAuto does, and records each call.
type fakeResolver struct {
	repo  *fakeExposureRepo
	calls []resolveCall
}

type resolveCall struct {
	tenant shared.ID
	source string
	fps    []string
	note   string
}

func (f *fakeResolver) ResolveAuto(_ context.Context, tenantID shared.ID, source string, fps []string, note string) (int, error) {
	f.calls = append(f.calls, resolveCall{tenantID, source, fps, note})
	n := 0
	for _, fp := range fps {
		if e, ok := f.repo.byFingerprint[fp]; ok && e.TenantID() == tenantID && e.Source() == source && e.IsActive() {
			if err := e.Resolve(shared.ID{}, note); err == nil {
				n++
			}
		}
	}
	return n, nil
}

const (
	fpExpired = "1111111111111111111111111111111111111111111111111111111111111111"
	fpGood    = "2222222222222222222222222222222222222222222222222222222222222222"
)

func certAsset(t *testing.T, tenant shared.ID, fp string, sans []any, notBefore, notAfter time.Time) *asset.Asset {
	t.Helper()
	return newAsset(t, tenant, fp, asset.AssetTypeCertificate, "", map[string]any{
		"fingerprint": fp,
		"certificate": map[string]any{
			"fingerprint": fp,
			"subject_cn":  sans[0],
			"sans":        sans,
			"issuer_cn":   "Example Issuer",
			"not_before":  notBefore.UTC().Format(time.RFC3339),
			"not_after":   notAfter.UTC().Format(time.RFC3339),
			"expired":     notAfter.Before(time.Now()),
		},
	})
}

// serviceAsset is an http service named by its URL, as ingest stores it.
func serviceAsset(t *testing.T, tenant shared.ID, rawURL string, props map[string]any) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithSubType(rawURL, asset.AssetTypeService, "http", asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.SetTenantID(tenant)
	a.SetProperties(props)
	return a
}

func httpService(t *testing.T, tenant shared.ID, host, fp string, status int) *asset.Asset {
	t.Helper()
	return serviceAsset(t, tenant, "https://"+host, map[string]any{
		"host":            "192.0.2.10", // the address httpx reports; the URL's name is what is judged
		"tls_fingerprint": fp,
		"status_code":     float64(status),
		"cnames":          []any{"pages.hosting.example.net"},
	})
}

func eventsOn(repo *fakeExposureRepo, a *asset.Asset) []*exposure.ExposureEvent {
	var out []*exposure.ExposureEvent
	for _, e := range repo.byID {
		if e.AssetID() != nil && *e.AssetID() == a.ID() {
			out = append(out, e)
		}
	}
	return out
}

func find(evs []*exposure.ExposureEvent, t exposure.EventType, issue string) *exposure.ExposureEvent {
	for _, e := range evs {
		if e.EventType() != t {
			continue
		}
		if got, _ := e.Details()["issue"].(string); got == issue {
			return e
		}
	}
	return nil
}

// A host that resets every HTTP request (status 0) and serves another
// party's expired default certificate: the exposures are raised on the host
// from the handshake facts alone; the certificate's own expiry is not
// raised twice.
func TestHostCertificate_ResetHostWithForeignExpiredCertificate(t *testing.T) {
	repo := newFakeExposureRepo()
	res := &fakeResolver{repo: repo}
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	b.SetAutoResolver(res)
	tenant := shared.NewID()
	now := time.Now()
	cert := certAsset(t, tenant, fpExpired, []any{"ssl.default.hosting.example.net"}, now.Add(-800*24*time.Hour), now.Add(-400*24*time.Hour))
	svc := httpService(t, tenant, "promo.example.com", fpExpired, 0)

	if err := b.ProjectAssets(context.Background(), tenant, []*asset.Asset{cert, svc}); err != nil {
		t.Fatal(err)
	}
	evs := eventsOn(repo, svc)
	expired := find(evs, exposure.EventTypeCertificateExpired, "")
	foreign := find(evs, exposure.EventTypeSSLIssue, exposurebridge.CertIssueForeignCertificate)
	if expired == nil || foreign == nil || len(evs) != 2 {
		t.Fatalf("host events %d: expired %v foreign %v", len(evs), expired != nil, foreign != nil)
	}
	if expired.Severity() != exposure.SeverityHigh || foreign.Severity() != exposure.SeverityHigh {
		t.Fatalf("severities %s %s", expired.Severity(), foreign.Severity())
	}
	d := foreign.Details()
	if d["domain"] != "promo.example.com" || d["cert_fingerprint"] != fpExpired || d["takeover_candidate"] != true || d["http_answered"] != false {
		t.Fatalf("details %v", d)
	}
	if !strings.Contains(expired.Title(), "promo.example.com") {
		t.Fatalf("title %q", expired.Title())
	}
	if got := eventsOn(repo, cert); find(got, exposure.EventTypeCertificateExpired, "") != nil {
		t.Fatal("the certificate's own expiry is raised next to the host's")
	}
	// The certificate-level expiry of earlier releases is resolved as superseded.
	var superseded bool
	for _, c := range res.calls {
		if c.note == exposurebridge.AutoResolveSupersededNote && c.tenant == tenant && c.source == exposurebridge.SourceReconScan && len(c.fps) == 2 {
			superseded = true
		}
	}
	if !superseded {
		t.Fatalf("resolver calls %+v", res.calls)
	}
}

// A certificate of the host's own domain that does not cover the name is a
// mismatch (medium), not a foreign certificate; a wildcard covers one label.
func TestHostCertificate_NameCoverage(t *testing.T) {
	now := time.Now()
	cases := []struct {
		host  string
		sans  []any
		issue string // "" no name problem
		sev   exposure.Severity
	}{
		{"shop.example.com", []any{"www.example.com", "example.com"}, exposurebridge.CertIssueNameMismatch, exposure.SeverityMedium},
		{"shop.example.com", []any{"*.example.com"}, "", ""},
		{"a.shop.example.com", []any{"*.example.com"}, exposurebridge.CertIssueNameMismatch, exposure.SeverityMedium},
		{"shop.example.com", []any{"shop.example.com"}, "", ""},
		{"shop.example.com", []any{"*.other.example.org"}, exposurebridge.CertIssueForeignCertificate, exposure.SeverityHigh},
		{"shop.example.com", []any{"SHOP.EXAMPLE.COM"}, "", ""},
	}
	for _, c := range cases {
		repo := newFakeExposureRepo()
		b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
		tenant := shared.NewID()
		cert := certAsset(t, tenant, fpGood, c.sans, now.Add(-time.Hour), now.Add(200*24*time.Hour))
		svc := httpService(t, tenant, c.host, fpGood, 200)
		_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{svc, cert})
		evs := eventsOn(repo, svc)
		if c.issue == "" {
			if len(evs) != 0 {
				t.Errorf("%s %v: unexpected %d events", c.host, c.sans, len(evs))
			}
			continue
		}
		e := find(evs, exposure.EventTypeSSLIssue, c.issue)
		if e == nil || e.Severity() != c.sev || len(evs) != 1 {
			t.Errorf("%s %v: want %s %s, got %d events", c.host, c.sans, c.issue, c.sev, len(evs))
		}
	}
}

func TestHostCertificate_ExpiringAndNotYetValid(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name    string
		nb, na  time.Time
		typ     exposure.EventType
		issue   string
		wantSev exposure.Severity
	}{
		{"expires in 20 days", now.Add(-time.Hour), now.Add(20 * 24 * time.Hour), exposure.EventTypeCertificateExpiring, "", exposure.SeverityMedium},
		{"expires in 3 days", now.Add(-time.Hour), now.Add(3 * 24 * time.Hour), exposure.EventTypeCertificateExpiring, "", exposure.SeverityHigh},
		{"not valid yet", now.Add(24 * time.Hour), now.Add(200 * 24 * time.Hour), exposure.EventTypeSSLIssue, exposurebridge.CertIssueNotYetValid, exposure.SeverityMedium},
	} {
		repo := newFakeExposureRepo()
		b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
		tenant := shared.NewID()
		cert := certAsset(t, tenant, fpGood, []any{"app.example.com"}, c.nb, c.na)
		svc := httpService(t, tenant, "app.example.com", fpGood, 200)
		_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{cert, svc})
		e := find(eventsOn(repo, svc), c.typ, c.issue)
		if e == nil || e.Severity() != c.wantSev {
			t.Errorf("%s: got %v", c.name, e)
		}
	}
}

// Re-ingesting the same host and certificate raises nothing new; a later
// scan that sees the host serve a good certificate resolves its exposures,
// and one that sees the problem again reopens them.
func TestHostCertificate_DedupAndAutoResolve(t *testing.T) {
	repo := newFakeExposureRepo()
	res := &fakeResolver{repo: repo}
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	b.SetAutoResolver(res)
	tenant := shared.NewID()
	now := time.Now()
	bad := certAsset(t, tenant, fpExpired, []any{"app.example.com"}, now.Add(-400*24*time.Hour), now.Add(-24*time.Hour))
	svc := httpService(t, tenant, "app.example.com", fpExpired, 200)

	_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{bad, svc})
	creates := repo.createCalls
	_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{bad, svc})
	if repo.createCalls != creates {
		t.Fatalf("re-ingest created %d more", repo.createCalls-creates)
	}
	expired := find(eventsOn(repo, svc), exposure.EventTypeCertificateExpired, "")
	if expired == nil || !expired.IsActive() {
		t.Fatal("no active expired exposure")
	}

	good := certAsset(t, tenant, fpGood, []any{"app.example.com"}, now.Add(-time.Hour), now.Add(300*24*time.Hour))
	svc.SetProperties(map[string]any{"tls_fingerprint": fpGood, "status_code": float64(200), "host": "192.0.2.10"})
	_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{good, svc})
	if expired.State() != exposure.StateResolved || expired.ResolutionNotes() != exposurebridge.AutoResolveCertNote {
		t.Fatalf("after a good certificate: state %s notes %q", expired.State(), expired.ResolutionNotes())
	}

	svc.SetProperties(map[string]any{"tls_fingerprint": fpExpired, "status_code": float64(0), "host": "192.0.2.10"})
	_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{bad, svc})
	if !expired.IsActive() {
		t.Fatalf("the problem seen again did not reopen it: %s", expired.State())
	}
}

// Assets of another tenant never pair, and every resolution is scoped to the
// ingest tenant.
func TestHostCertificate_TenantIsolation(t *testing.T) {
	repo := newFakeExposureRepo()
	res := &fakeResolver{repo: repo}
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	b.SetAutoResolver(res)
	tenant, other := shared.NewID(), shared.NewID()
	now := time.Now()
	foreignTenantCert := certAsset(t, other, fpExpired, []any{"x.example.net"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	svc := httpService(t, tenant, "app.example.com", fpExpired, 0)
	otherSvc := httpService(t, other, "app.example.com", fpExpired, 0)

	_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{foreignTenantCert, svc, otherSvc})
	if len(eventsOn(repo, svc)) != 0 || len(eventsOn(repo, otherSvc)) != 0 {
		t.Fatal("a certificate of another tenant was judged for this tenant's host")
	}
	for _, e := range repo.byID {
		if e.TenantID() != tenant {
			t.Fatalf("event for another tenant: %v", e.TenantID())
		}
	}
	for _, c := range res.calls {
		if c.tenant != tenant {
			t.Fatalf("resolution for another tenant: %+v", c)
		}
	}
	if slices.ContainsFunc(res.calls, func(c resolveCall) bool { return len(c.fps) > 0 }) {
		t.Fatalf("resolved something without a pair: %+v", res.calls)
	}
}

// A service probed by address is judged on validity, never on names.
func TestHostCertificate_AddressHostOnlyValidity(t *testing.T) {
	repo := newFakeExposureRepo()
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	tenant := shared.NewID()
	now := time.Now()
	cert := certAsset(t, tenant, fpExpired, []any{"app.example.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	svc := serviceAsset(t, tenant, "https://192.0.2.10:8443", map[string]any{"tls_fingerprint": fpExpired})
	_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{cert, svc})
	evs := eventsOn(repo, svc)
	if len(evs) != 1 || find(evs, exposure.EventTypeCertificateExpired, "") == nil || evs[0].Details()["domain"] != "192.0.2.10" {
		t.Fatalf("events %d", len(evs))
	}
}

// A stored certificate asset carries flat properties (is_expired,
// fingerprint_sha256): the certificate-level projection reads them too, so a
// certificate seen without a serving host still raises its expiry.
func TestCertificateEvents_StoredFlatShape(t *testing.T) {
	repo := newFakeExposureRepo()
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	tenant := shared.NewID()
	cert := newAsset(t, tenant, fpExpired, asset.AssetTypeCertificate, "", map[string]any{
		"fingerprint_sha256": fpExpired, "subject_cn": "app.example.com", "is_expired": true, "is_self_signed": true,
		"not_after": time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
	})
	_ = b.ProjectAssets(context.Background(), tenant, []*asset.Asset{cert})
	evs := eventsOn(repo, cert)
	if find(evs, exposure.EventTypeCertificateExpired, "") == nil || find(evs, exposure.EventTypeSSLIssue, "self-signed") == nil {
		t.Fatalf("events %d", len(evs))
	}
}

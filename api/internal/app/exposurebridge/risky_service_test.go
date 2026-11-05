package exposurebridge_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/exposurebridge"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func portAsset(t *testing.T, tenant shared.ID, name string, port int, kind string, src asset.KindSource, extra map[string]any) *asset.Asset {
	t.Helper()
	props := map[string]any{"port": float64(port), "transport": "tcp"}
	if kind != "" {
		def, ok := asset.LookupServiceKind(kind)
		if !ok {
			t.Fatalf("unknown kind %s", kind)
		}
		props[asset.PropKeyServiceKind] = kind
		props[asset.PropKeyServiceCategory] = def.Category
		props[asset.PropKeyKindSource] = string(src)
	}
	for k, v := range extra {
		props[k] = v
	}
	return newAsset(t, tenant, name, asset.AssetTypeService, "open_port", props)
}

func riskyEvents(repo *fakeExposureRepo) []*exposure.ExposureEvent {
	var out []*exposure.ExposureEvent
	for _, e := range repo.byID {
		if e.EventType() == exposure.EventTypeRiskyServiceExposed {
			out = append(out, e)
		}
	}
	return out
}

func project(t *testing.T, b *exposurebridge.AssetBridge, tenant shared.ID, a *asset.Asset) {
	t.Helper()
	if err := b.ProjectAssets(context.Background(), tenant, []*asset.Asset{a}); err != nil {
		t.Fatal(err)
	}
}

// The exposure rules: which open ports raise a risky service exposure, and
// at which severity.
func TestRiskyService_Rules(t *testing.T) {
	cases := []struct {
		name  string
		host  string
		port  int
		kind  string
		src   asset.KindSource
		extra map[string]any
		want  exposure.Severity // "" = no exposure
	}{
		{"fingerprinted rdp on a public address", "198.51.100.7", 3389, "rdp", asset.KindSourceFingerprint, nil, exposure.SeverityHigh},
		{"reported smb", "198.51.100.7", 445, "smb", asset.KindSourceReported, nil, exposure.SeverityHigh},
		{"modbus is critical", "198.51.100.7", 502, "modbus", asset.KindSourceFingerprint, nil, exposure.SeverityCritical},
		{"redis without auth is critical", "198.51.100.7", 6379, "redis", asset.KindSourceFingerprint,
			map[string]any{asset.PropKeyHasAnonymousAccess: true}, exposure.SeverityCritical},
		{"redis with unknown auth is high", "198.51.100.7", 6379, "redis", asset.KindSourceFingerprint, nil, exposure.SeverityHigh},
		{"a port guess never raises one", "198.51.100.7", 3389, "rdp", asset.KindSourcePortGuess, nil, ""},
		{"no kind", "198.51.100.7", 3389, "", "", nil, ""},
		{"ssh is not risky by kind", "198.51.100.7", 22, "ssh", asset.KindSourceFingerprint, nil, ""},
		{"web is not risky by kind", "198.51.100.7", 443, "http", asset.KindSourceFingerprint, nil, ""},
		{"private address", "10.0.0.5", 3389, "rdp", asset.KindSourceFingerprint, nil, ""},
		{"shared address space", "100.64.1.1", 3389, "rdp", asset.KindSourceFingerprint, nil, ""},
		{"loopback", "127.0.0.1", 3389, "rdp", asset.KindSourceFingerprint, nil, ""},
		{"closed port", "198.51.100.7", 3389, "rdp", asset.KindSourceFingerprint, map[string]any{"state": "closed"}, ""},
		{"public ipv6", "[2600:1f18::5]", 3389, "rdp", asset.KindSourceFingerprint, nil, exposure.SeverityHigh},
		{"forged source", "198.51.100.7", 3389, "rdp", asset.KindSource("bogus"), nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeExposureRepo()
			b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
			tenant := shared.NewID()
			a := portAsset(t, tenant, tc.host+":"+strconv.Itoa(tc.port)+":tcp", tc.port, tc.kind, tc.src, tc.extra)
			project(t, b, tenant, a)
			evs := riskyEvents(repo)
			if tc.want == "" {
				if len(evs) != 0 {
					t.Fatalf("got %d risky exposures, want none", len(evs))
				}
				return
			}
			if len(evs) != 1 {
				t.Fatalf("got %d risky exposures, want 1", len(evs))
			}
			if evs[0].Severity() != tc.want {
				t.Errorf("severity %s, want %s", evs[0].Severity(), tc.want)
			}
			if evs[0].TenantID() != tenant || evs[0].AssetID() == nil || *evs[0].AssetID() != a.ID() {
				t.Errorf("exposure not bound to the asset and its tenant")
			}
		})
	}
}

// An explicit exposure decides: public counts, private does not.
func TestRiskyService_ExposureDecides(t *testing.T) {
	tenant := shared.NewID()
	repo := newFakeExposureRepo()
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	pub := portAsset(t, tenant, "db.example.com:5432:tcp", 5432, "postgresql", asset.KindSourceFingerprint, nil)
	pub.SetExposure(asset.ExposurePublic)
	project(t, b, tenant, pub)
	if len(riskyEvents(repo)) != 1 {
		t.Fatal("public exposure did not raise one")
	}
	repo2 := newFakeExposureRepo()
	b2 := exposurebridge.NewAssetBridge(repo2, nil, testLogger())
	priv := portAsset(t, tenant, "198.51.100.8:5432:tcp", 5432, "postgresql", asset.KindSourceFingerprint, nil)
	priv.SetExposure(asset.ExposurePrivate)
	project(t, b2, tenant, priv)
	if len(riskyEvents(repo2)) != 0 {
		t.Fatal("private exposure raised one")
	}
}

// A kind change, a measured anonymous access or a downgrade to a guess
// resolves the exposures the port no longer raises; a re-scan dedupes.
func TestRiskyService_ReclassificationResolves(t *testing.T) {
	tenant := shared.NewID()
	repo := newFakeExposureRepo()
	res := &fakeResolver{repo: repo}
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	b.SetAutoResolver(res)

	a := portAsset(t, tenant, "198.51.100.9:6379:tcp", 6379, "redis", asset.KindSourceFingerprint, nil)
	project(t, b, tenant, a)
	project(t, b, tenant, a)
	if n := len(riskyEvents(repo)); n != 1 {
		t.Fatalf("re-scan: %d risky exposures, want 1", n)
	}
	first := riskyEvents(repo)[0]

	// The probe now sees it answer without credentials: a critical one, the
	// high one resolved.
	props := a.Properties()
	props[asset.PropKeyHasAnonymousAccess] = true
	a.SetProperties(props)
	project(t, b, tenant, a)
	if first.IsActive() {
		t.Error("the high exposure stayed open after anonymous access was seen")
	}
	var critical *exposure.ExposureEvent
	for _, e := range riskyEvents(repo) {
		if e.IsActive() {
			critical = e
		}
	}
	if critical == nil || critical.Severity() != exposure.SeverityCritical {
		t.Fatalf("no open critical exposure: %v", critical)
	}

	// The port turns out to be something not risky: all resolved.
	props = a.Properties()
	props[asset.PropKeyServiceKind] = "http"
	props[asset.PropKeyServiceCategory] = "web"
	a.SetProperties(props)
	project(t, b, tenant, a)
	for _, e := range riskyEvents(repo) {
		if e.IsActive() {
			t.Errorf("exposure %q stayed open after the kind changed", e.Title())
		}
	}
	for _, c := range res.calls {
		if c.tenant != tenant || c.source != exposurebridge.SourceReconScan {
			t.Errorf("resolution outside the asset's tenant or source: %+v", c)
		}
	}
}

// A risky asset of another tenant in the batch raises nothing and resolves
// nothing.
func TestRiskyService_CrossTenant(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	repo := newFakeExposureRepo()
	res := &fakeResolver{repo: repo}
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	b.SetAutoResolver(res)
	a := portAsset(t, other, "198.51.100.10:3389:tcp", 3389, "rdp", asset.KindSourceFingerprint, nil)
	project(t, b, tenant, a)
	if len(repo.byID) != 0 {
		t.Fatalf("cross-tenant asset projected %d exposures", len(repo.byID))
	}
	for _, c := range res.calls {
		if len(c.fps) > 0 {
			t.Fatalf("cross-tenant asset resolved exposures: %+v", c)
		}
	}
}

// The port_open exposure keeps its identity when a kind is learned: the
// transport is the key, never the application protocol, and the kind is a
// detail; a guess is only ever named as a guess.
func TestPortOpen_KeyStableAcrossClassification(t *testing.T) {
	tenant := shared.NewID()
	repo := newFakeExposureRepo()
	b := exposurebridge.NewAssetBridge(repo, nil, testLogger())
	legacy := portAsset(t, tenant, "198.51.100.11:22:tcp", 22, "", "", map[string]any{"protocol": "tcp"})
	delete(legacy.Properties(), "transport")
	project(t, b, tenant, legacy)
	before := firstEventOfType(repo, exposure.EventTypePortOpen)
	if before == nil {
		t.Fatal("no port_open")
	}

	// The same asset after a detection named the protocol.
	repo2 := newFakeExposureRepo()
	b2 := exposurebridge.NewAssetBridge(repo2, nil, testLogger())
	legacy.SetProperties(map[string]any{
		"port": float64(22), "transport": "tcp", "protocol": "ssh",
		asset.PropKeyServiceKind: "ssh", asset.PropKeyServiceCategory: "remote_access", asset.PropKeyKindSource: "fingerprint",
	})
	project(t, b2, tenant, legacy)
	after := firstEventOfType(repo2, exposure.EventTypePortOpen)
	if after == nil || after.Fingerprint() != before.Fingerprint() {
		t.Fatalf("port_open re-keyed: %v vs %v", before.Fingerprint(), after)
	}
	if after.Details()["service_label"] != "SSH" {
		t.Errorf("measured kind not named: %v", after.Details())
	}

	// A guess is named only as a guess.
	repo3 := newFakeExposureRepo()
	b3 := exposurebridge.NewAssetBridge(repo3, nil, testLogger())
	legacy.SetProperties(map[string]any{
		"port": float64(22), "transport": "tcp",
		asset.PropKeyServiceKind: "ssh", asset.PropKeyServiceCategory: "remote_access", asset.PropKeyKindSource: "port_guess",
	})
	project(t, b3, tenant, legacy)
	g := firstEventOfType(repo3, exposure.EventTypePortOpen)
	if g.Fingerprint() != before.Fingerprint() {
		t.Error("port_open re-keyed by a guess")
	}
	if g.Details()["service_label"] != nil || g.Details()["service_guess"] != "SSH" {
		t.Errorf("guess not marked as a guess: %v", g.Details())
	}
	if s := exposure.SummaryOf(g.EventType(), g.Title(), g.Details()); s.Variant != "guess" {
		t.Errorf("summary variant %q, want guess", s.Variant)
	}
}

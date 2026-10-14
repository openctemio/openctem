package assetfreshness

import (
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestClassesForTool(t *testing.T) {
	cases := []struct {
		tool string
		typ  asset.AssetType
		want []Class
	}{
		{"dnsx", asset.AssetTypeSubdomain, []Class{ClassDNS}},
		{"dnsx", asset.AssetTypeIPAddress, nil}, // resolver output address: not a DNS observation of the address
		{"rdap", asset.AssetTypeDomain, []Class{ClassRegistration}},
		{"rdap", asset.AssetTypeSubdomain, nil},
		{"asn", asset.AssetTypeIPAddress, []Class{ClassNetworkOwner}},
		{"httpx", asset.AssetTypeCertificate, []Class{ClassTLS}},
		{"httpx", asset.AssetTypeService, []Class{ClassHTTP}},
		{"naabu", asset.AssetTypeIPAddress, []Class{ClassPorts}},
		{"nuclei", asset.AssetTypeSubdomain, nil},
		{"unknown-tool", asset.AssetTypeDomain, nil},
		{"", asset.AssetTypeDomain, nil},
	}
	for _, c := range cases {
		got := ClassesForTool(stagetest.Catalog(), c.tool, c.typ)
		if !slices.Equal(got, c.want) {
			t.Errorf("ClassesForTool(%q, %s) = %v, want %v", c.tool, c.typ, got, c.want)
		}
	}
}

func TestTTL_ImportantAssetsHalfAndBounds(t *testing.T) {
	dns, _ := Lookup(ClassDNS)
	if got := dns.TTL(Importance{Criticality: asset.CriticalityLow}); got != 24*time.Hour {
		t.Fatalf("low dns ttl = %s", got)
	}
	if got := dns.TTL(Importance{Criticality: asset.CriticalityCritical}); got != 12*time.Hour {
		t.Fatalf("critical dns ttl = %s", got)
	}
	if got := dns.TTL(Importance{InternetFacing: true}); got != 12*time.Hour {
		t.Fatalf("internet-facing dns ttl = %s", got)
	}
	tiny := ClassSpec{BaseTTL: time.Hour}
	if got := tiny.TTL(Importance{}); got != MinTTL {
		t.Fatalf("floor not applied: %s", got)
	}
}

func TestView_StatesAndNever(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	id := shared.NewID()
	imp := Importance{Criticality: asset.CriticalityMedium}

	// A domain nobody observed: both passive classes are never, active ones absent.
	v := View(asset.AssetTypeDomain, imp, nil, now)
	if v.State != StateNever || len(v.Classes) != 2 {
		t.Fatalf("unobserved domain = %+v", v)
	}

	// DNS fresh, registration 10 days old (stale under 7 d, dead after 21 d).
	obs := []Observation{
		{AssetID: id, Class: ClassDNS, ObservedAt: now.Add(-2 * time.Hour), Source: "dnsx"},
		{AssetID: id, Class: ClassRegistration, ObservedAt: now.Add(-10 * 24 * time.Hour), Source: "rdap"},
	}
	v = View(asset.AssetTypeDomain, imp, obs, now)
	if v.State != StateStale {
		t.Fatalf("state = %s, want stale", v.State)
	}
	if v.NextDueAt == nil || !v.NextDueAt.Equal(now.Add(-10*24*time.Hour).Add(7*24*time.Hour)) {
		t.Fatalf("next due = %v", v.NextDueAt)
	}

	obs[1].ObservedAt = now.Add(-30 * 24 * time.Hour)
	if v = View(asset.AssetTypeDomain, imp, obs, now); v.State != StateDead {
		t.Fatalf("state = %s, want dead", v.State)
	}

	// An active class shows only once observed.
	obs = append(obs[:1], Observation{AssetID: id, Class: ClassHTTP, ObservedAt: now, Source: "httpx"})
	v = View(asset.AssetTypeSubdomain, imp, obs, now)
	if v.State != StateLive || len(v.Classes) != 2 {
		t.Fatalf("subdomain = %+v", v)
	}

	// A type with no class at all is live with no classes.
	if v = View(asset.AssetTypeRepository, imp, nil, now); v.State != StateLive || len(v.Classes) != 0 {
		t.Fatalf("repository = %+v", v)
	}
}

func TestPassiveClassesFor(t *testing.T) {
	if got := PassiveClassesFor(asset.AssetTypeDomain); !slices.Equal(got, []Class{ClassDNS, ClassRegistration}) {
		t.Fatalf("domain = %v", got)
	}
	if got := PassiveClassesFor(asset.AssetTypeIPAddress); !slices.Equal(got, []Class{ClassNetworkOwner}) {
		t.Fatalf("ip = %v", got)
	}
	if got := PassiveClassesFor(asset.AssetTypeRepository); len(got) != 0 {
		t.Fatalf("repository = %v", got)
	}
}

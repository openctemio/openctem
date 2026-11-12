package exploration

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Every action's tier is the stage catalog's (the generator copies it).
func TestCatalog_TiersFromStageCatalog(t *testing.T) {
	if len(LeadTypes()) < 3 {
		t.Fatal("the catalog lost its lead types")
	}
	for _, lt := range LeadTypes() {
		for _, a := range lt.Actions {
			st, ok := stage.Lookup(stage.Key(a.Capability))
			if !ok || st.Tier != a.Tier {
				t.Errorf("%s %s: tier %v, stage catalog %v (%v)", lt.ID, a.Capability, a.Tier, st.Tier, ok)
			}
		}
	}
}

func TestCatalog_ActionFor(t *testing.T) {
	gone, ok := LookupLeadType("asset.gone_with_findings")
	if !ok {
		t.Fatal("asset.gone_with_findings missing")
	}
	cases := map[asset.AssetType]string{
		asset.AssetTypeSubdomain: "resolve.dns",
		asset.AssetTypeIPAddress: "discover.hosts",
		asset.AssetTypeHost:      "probe.http",
	}
	for typ, want := range cases {
		a, ok := gone.ActionFor(typ, "")
		if !ok || a.Capability != want {
			t.Errorf("%s: got %q (%v), want %s", typ, a.Capability, ok, want)
		}
	}
	if _, ok := gone.ActionFor(asset.AssetTypeRepository, ""); ok {
		t.Error("a repository has no liveness step")
	}
}

func TestCheckCatalog(t *testing.T) {
	mk := func(typ, capability, reason string, params map[string]any) *Lead {
		a := shared.NewID()
		l, err := NewLead(NewLeadInput{TenantID: shared.NewID(), ExplorationID: shared.NewID(), Type: typ,
			Action: Action{Capability: capability, Params: params}, SubjectAssetID: &a, ReasonCode: reason,
			Origin: OriginUser, OriginRef: "user:x"})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if _, err := CheckCatalog(mk("dns.takeover_check", "check.takeover", "cname_dangling", nil)); err != nil {
		t.Fatalf("valid lead refused: %v", err)
	}
	bad := map[string]*Lead{
		"unknown type":      mk("dns.zone_transfer", "resolve.dns", "cname_dangling", nil),
		"undeclared action": mk("dns.takeover_check", "dast.web", "cname_dangling", nil),
		"unknown reason":    mk("dns.takeover_check", "check.takeover", "because", nil),
		"undeclared param":  mk("dns.takeover_check", "check.takeover", "cname_dangling", map[string]any{"templates": "all"}),
	}
	for name, l := range bad {
		if _, err := CheckCatalog(l); !errors.Is(err, ErrNotInCatalog) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

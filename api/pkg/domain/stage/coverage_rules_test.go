package stage

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// platformChecks are coverage capabilities the platform runs itself (no
// stage, no sensor): the DNS checks of the attack-surface module.
var platformChecks = map[string]bool{"dns.dangling": true, "dns.email": true}

// Every coverage rule of the registry names a stage that takes the type, or
// a platform check; a rule's expected output is something that stage may
// produce. A rule that names a stage which cannot take the type would be a
// pair that is never covered.
func TestCoverageRules_NameStagesThatTakeTheType(t *testing.T) {
	n := 0
	for _, d := range asset.RegistryDocument().Types {
		ref := asset.TypeRef{Type: d.Type}
		if d.AliasOf != nil {
			ref = *d.AliasOf
		}
		for _, r := range d.Coverage {
			n++
			if platformChecks[r.Capability] {
				continue
			}
			s, ok := Lookup(Key(r.Capability))
			if !ok {
				t.Errorf("%s: coverage capability %q is not a stage or a platform check", d.Type, r.Capability)
				continue
			}
			if !s.Accepts(ref) {
				t.Errorf("%s: stage %s does not take %s", d.Type, r.Capability, Label(ref))
			}
			if r.Expects != "" {
				exp := asset.CanonicalPair(asset.AssetType(r.Expects), "")
				if !s.Produces(exp) {
					t.Errorf("%s: stage %s never produces the expected %s", d.Type, r.Capability, r.Expects)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("the registry has no coverage rules")
	}
}

// The coverage rules of the network chain are what research/141 decided:
// a name is resolved and probed, an open web port is probed, an origin gets
// templates. Losing one of these silently is the failure the ledger exists
// to show.
func TestCoverageRules_NetworkChain(t *testing.T) {
	has := func(typ asset.AssetType, sub, capability string) bool {
		for _, r := range asset.CoverageRules(typ, sub) {
			if r.Capability == capability {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		typ        asset.AssetType
		sub, capab string
	}{
		{asset.AssetTypeDomain, "", "discover.subdomains"},
		{asset.AssetTypeSubdomain, "", "resolve.dns"},
		{asset.AssetTypeSubdomain, "", "probe.http"},
		{asset.AssetTypeIPAddress, "", "scan.ports"},
		{"service", "open_port", "probe.http"},
		{"service", "http", "vuln.templates"},
	} {
		if !has(c.typ, c.sub, c.capab) {
			t.Errorf("%s/%s lacks %s", c.typ, c.sub, c.capab)
		}
	}
	if len(asset.CoverageRules("service", "")) != 0 {
		t.Error("a service without a sub-type has coverage rules")
	}
}

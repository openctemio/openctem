package stage

import "testing"

// A passive stage never reaches its targets; every other stage does.
func TestCatalog_PassiveStagesDeclareANonTargetNetwork(t *testing.T) {
	for _, s := range All() {
		touches := s.NetworkOf().TouchesTargets()
		if s.Tier.Passive() && touches {
			t.Errorf("%s is T0 but its network %q reaches the targets", s.Key, s.NetworkOf())
		}
		if !s.Tier.Passive() && !touches {
			t.Errorf("%s is %s but declares the non-target network %q", s.Key, s.Tier, s.NetworkOf())
		}
	}
}

func TestToolNetwork(t *testing.T) {
	cases := map[string]Network{
		"subfinder": NetworkEgressProxy,
		"dnsx":      NetworkResolver,
		"rdap":      NetworkEgressProxy,
		"asn":       NetworkEgressProxy,
		"semgrep":   NetworkVendor,
		"trivy":     NetworkVendor,
		"naabu":     NetworkTargets,
		"nuclei":    NetworkTargets,
		"zap":       NetworkTargets,
		"made-up":   NetworkTargets, // unknown: fail closed
	}
	for tool, want := range cases {
		if got := ToolNetwork(tool); got != want {
			t.Errorf("ToolNetwork(%s) = %q, want %q", tool, got, want)
		}
	}
	if Network("bogus").TouchesTargets() == false {
		t.Error("an unknown network must count as reaching the targets")
	}
}

func TestIntensityTier(t *testing.T) {
	cases := []struct {
		name   string
		tool   string
		caps   []string
		config map[string]any
		want   Tier
	}{
		{"passive tool", "subfinder", nil, nil, TierPassive},
		{"passive capability", "", []string{"resolve.dns"}, nil, TierPassive},
		{"active capability", "", []string{"probe.http"}, nil, TierActive},
		{"intrusive tool", "zap", nil, nil, TierIntrusive},
		{"intrusive capability", "", []string{"dast.web"}, nil, TierIntrusive},
		{"unknown step", "", []string{"recon"}, nil, TierActive},
		{"unknown tool", "custom-thing", nil, nil, TierActive},
		{"tool tier wins over a lower capability", "naabu", []string{"resolve.dns"}, nil, TierActive},
		{"dnsx with recursive resolvers", "dnsx", nil, map[string]any{"retries": 2}, TierPassive},
		{"dnsx with custom resolvers", "dnsx", nil, map[string]any{"resolvers": []any{"203.0.113.53"}}, TierActive},
		{"resolve step with custom resolver", "", []string{"resolve.dns"}, map[string]any{"Resolver": "ns1.example.com"}, TierActive},
		{"empty resolver list stays passive", "dnsx", nil, map[string]any{"resolvers": []any{}}, TierPassive},
		{"resolvers key on a non-DNS tool is ignored", "subfinder", nil, map[string]any{"resolvers": "1.1.1.1"}, TierPassive},
	}
	for _, c := range cases {
		if got := IntensityTier(c.tool, c.caps, c.config); got != c.want {
			t.Errorf("%s: IntensityTier = %s, want %s", c.name, got, c.want)
		}
	}
}

// The passive lookups: T0, third-party sources only, run by the sensor's
// rdap and asn tools as capability jobs, with their standard params mapped;
// a lookup step counts as passive whatever its settings.
func TestLookupStages(t *testing.T) {
	for key, tool := range map[Key]string{LookupRDAP: "rdap", LookupASN: "asn"} {
		s, ok := Lookup(key)
		if !ok {
			t.Fatalf("%s not in the catalog", key)
		}
		if s.Tier != TierPassive || s.NetworkOf() != NetworkEgressProxy || s.DefaultTool() != tool || !TakesCapabilityJobs(s, tool) {
			t.Fatalf("%s: tier %s network %s tool %s", key, s.Tier, s.NetworkOf(), s.DefaultTool())
		}
		if got := IntensityTier(tool, []string{string(key)}, map[string]any{"resolvers": []any{"192.0.2.53"}}); got != TierPassive {
			t.Fatalf("%s step counts at %s", key, got)
		}
		if got := ProbeTier(tool); got != TierPassive {
			t.Fatalf("%s probes at %s", tool, got)
		}
	}
	asn, _ := Lookup(LookupASN)
	if !asn.Accepts(tIP) || !asn.Accepts(tNetwork) || asn.Accepts(tDomain) || !asn.Produces(tNetwork) {
		t.Fatal("lookup.asn ports")
	}
	rdap, _ := Lookup(LookupRDAP)
	if !rdap.Accepts(tDomain) || rdap.Accepts(tSubdomain) || rdap.Produces(tIP) {
		t.Fatal("lookup.rdap ports")
	}
	if miss := UnsupportedParams(asn, "asn", map[string]any{"include_announced": true, "max_ranges": 10}); len(miss) != 0 {
		t.Fatalf("asn params refused: %v", miss)
	}
	if miss := UnsupportedParams(rdap, "rdap", map[string]any{"follow_registrar": false}); len(miss) != 0 {
		t.Fatalf("rdap params refused: %v", miss)
	}
}

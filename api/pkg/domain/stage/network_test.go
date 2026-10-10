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

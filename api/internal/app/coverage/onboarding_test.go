package coverage

import (
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

const enumCap = string(stage.EnumerateSubdomains)

func root(name string, never bool, fail, platformFail int) covdom.DueTarget {
	return covdom.DueTarget{AssetID: shared.NewID(), Name: name, Type: asset.AssetTypeDomain,
		NeverCovered: never, FailStreak: fail, PlatformFailStreak: platformFail}
}

// The deep-versus-standard decision: only a root domain whose enumeration
// never succeeded, and has deep attempts left, is onboarded deep.
func TestOnboards(t *testing.T) {
	sub := root("www.example.com", true, 0, 0)
	sub.Type = asset.AssetTypeSubdomain
	for name, c := range map[string]struct {
		capability string
		d          covdom.DueTarget
		want       bool
	}{
		"new root":                         {enumCap, root("example.com", true, 0, 0), true},
		"new root, one failure":            {enumCap, root("example.com", true, 1, 0), true},
		"new root, two platform failures":  {enumCap, root("example.com", true, 0, 2), true},
		"already onboarded (once only)":    {enumCap, root("example.com", false, 0, 0), false},
		"deep attempts used: falls back":   {enumCap, root("example.com", true, 2, 1), false},
		"deep attempts used, target side":  {enumCap, root("example.com", true, OnboardingDeepAttempts, 0), false},
		"a subdomain is not a root":        {enumCap, sub, false},
		"another capability never deep":    {"discover.subdomains", root("example.com", true, 0, 0), false},
		"an active port scan never deep":   {"scan.ports", root("example.com", true, 0, 0), false},
		"a covered root that later failed": {enumCap, root("example.com", false, 1, 0), false},
	} {
		if got := onboards(c.capability, c.d); got != c.want {
			t.Errorf("%s: onboards = %v, want %v", name, got, c.want)
		}
	}
}

// A batch with new roots starts only them, deep, capped; the others stay
// due for the next pass. A batch without one runs whole at standard depth.
func TestOnboardingBatch(t *testing.T) {
	old := root("old.example.com", false, 0, 0)
	fresh := root("new.example.com", true, 0, 0)
	batch, depth := onboardingBatch(enumCap, []covdom.DueTarget{old, fresh})
	if depth != scanworkflow.DepthDeep || len(batch) != 1 || batch[0].AssetID != fresh.AssetID {
		t.Fatalf("mixed batch = %v at %s, want the new root alone, deep", batch, depth)
	}

	batch, depth = onboardingBatch(enumCap, []covdom.DueTarget{old})
	if depth != scanworkflow.DepthStandard || len(batch) != 1 {
		t.Fatalf("steady batch = %v at %s, want it whole at standard", batch, depth)
	}

	// Failure fallback: a root out of deep attempts goes with the steady batch.
	spent := root("spent.example.com", true, OnboardingDeepAttempts, 0)
	batch, depth = onboardingBatch(enumCap, []covdom.DueTarget{old, spent})
	if depth != scanworkflow.DepthStandard || len(batch) != 2 {
		t.Fatalf("batch with a spent root = %v at %s, want standard", batch, depth)
	}

	many := make([]covdom.DueTarget, 0, MaxOnboardingBatch+5)
	for i := range MaxOnboardingBatch + 5 {
		many = append(many, root(fmt.Sprintf("r%d.example.com", i), true, 0, 0))
	}
	batch, depth = onboardingBatch(enumCap, many)
	if depth != scanworkflow.DepthDeep || len(batch) != MaxOnboardingBatch {
		t.Fatalf("%d new roots: %d in the deep run, want %d", len(many), len(batch), MaxOnboardingBatch)
	}

	// Other capabilities are never split.
	batch, depth = onboardingBatch("probe.http", []covdom.DueTarget{fresh, old})
	if depth != scanworkflow.DepthStandard || len(batch) != 2 {
		t.Fatalf("probe.http batch = %v at %s", batch, depth)
	}
}

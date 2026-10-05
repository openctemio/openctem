package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestIsTakeoverOnlyProbe(t *testing.T) {
	cases := []struct {
		name    string
		scanner string
		config  map[string]any
		want    bool
	}{
		{"nuclei takeover []any", "nuclei", map[string]any{"tags": []any{"takeover"}}, true},
		{"nuclei takeover []string", "nuclei", map[string]any{"tags": []string{"takeover"}}, true},
		{"nuclei takeover string", "Nuclei", map[string]any{"tags": "takeover", "severity": "high"}, true},
		{"rate limit allowed", "nuclei", map[string]any{"tags": []any{" TAKEOVER "}, "rate_limit": 10}, true},
		{"two tags", "nuclei", map[string]any{"tags": []any{"takeover", "cve"}}, false},
		{"comma tags", "nuclei", map[string]any{"tags": "takeover,default-login"}, false},
		{"other tag", "nuclei", map[string]any{"tags": []any{"cve"}}, false},
		{"templates widen it", "nuclei", map[string]any{"tags": []any{"takeover"}, "templates": []any{"x.yaml"}}, false},
		{"template ids widen it", "nuclei", map[string]any{"tags": []any{"takeover"}, "template_ids": []any{"a"}}, false},
		{"no config", "nuclei", nil, false},
		{"no tags", "nuclei", map[string]any{"severity": "high"}, false},
		{"non-string tag", "nuclei", map[string]any{"tags": []any{1}}, false},
		{"other scanner", "httpx", map[string]any{"tags": []any{"takeover"}}, false},
	}
	for _, c := range cases {
		if got := IsTakeoverOnlyProbe(c.scanner, c.config); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// takeoverStub is a gate with the takeover exception.
type takeoverStub struct {
	stubGate
	admitted map[string]bool
	err      error
	asked    []string
}

func (g *takeoverStub) TakeoverAdmittedAssets(_ context.Context, _ shared.ID, ids []string) (map[string]bool, error) {
	g.asked = append(g.asked, ids...)
	return g.pick(ids)
}

func (g *takeoverStub) TakeoverAdmittedTargets(_ context.Context, _ shared.ID, targets []string) (map[string]bool, error) {
	g.asked = append(g.asked, targets...)
	return g.pick(targets)
}

func (g *takeoverStub) pick(keys []string) (map[string]bool, error) {
	if g.err != nil {
		return nil, g.err
	}
	out := map[string]bool{}
	for _, k := range keys {
		if g.admitted[k] {
			out[k] = true
		}
	}
	return out, nil
}

// research/22 E13: a takeover-only scan may target a dependency the gate
// admits; any other state, any other scan, or a failed lookup is refused.
func TestRefuseUnownedTargets_TakeoverException(t *testing.T) {
	gate := &takeoverStub{
		stubGate: stubGate{blockedTyped: map[string]attribution.State{
			"saas.example.com":    attribution.StateDependency, // open dangling_cname
			"cdn.example.com":     attribution.StateDependency, // none
			"review.example.com":  attribution.StateNeedsReview,
			"notours.example.com": attribution.StateRejected,
		}},
		admitted: map[string]bool{"saas.example.com": true, "review.example.com": true, "notours.example.com": true},
	}
	svc := &Service{attributionGate: gate, logger: logger.NewNop()}
	tenant := shared.NewID()
	ctx := context.Background()

	if err := svc.refuseUnownedTargets(ctx, tenant, "quick_scan", []string{"saas.example.com"}, true); err != nil {
		t.Fatalf("takeover-only scan of an admitted dependency refused: %v", err)
	}
	if err := svc.refuseUnownedTargets(ctx, tenant, "quick_scan", []string{"saas.example.com"}, false); err == nil {
		t.Fatal("an ordinary scan of a dependency was admitted")
	}
	for _, target := range []string{"cdn.example.com", "review.example.com", "notours.example.com"} {
		if err := svc.refuseUnownedTargets(ctx, tenant, "quick_scan", []string{target}, true); err == nil {
			t.Fatalf("%s admitted to a takeover-only scan", target)
		}
	}
	// Only dependency entries are ever put to the takeover check.
	for _, k := range gate.asked {
		if k == "review.example.com" || k == "notours.example.com" {
			t.Fatalf("non-dependency %s was put to the takeover check", k)
		}
	}
	gate.err = errors.New("db down")
	if err := svc.refuseUnownedTargets(ctx, tenant, "quick_scan", []string{"saas.example.com"}, true); err == nil {
		t.Fatal("a failed takeover lookup must refuse")
	}
	// A gate without the exception admits nothing.
	plain := &Service{attributionGate: &gate.stubGate, logger: logger.NewNop()}
	if err := plain.refuseUnownedTargets(ctx, tenant, "quick_scan", []string{"saas.example.com"}, true); err == nil {
		t.Fatal("a gate without the takeover exception admitted a dependency")
	}
}

// A scan run (manual, scheduled, retry) applies the same exception to its
// typed targets.
func TestResolveScanTargets_TakeoverException(t *testing.T) {
	gate := &takeoverStub{
		stubGate: stubGate{blockedTyped: map[string]attribution.State{"saas.example.com": attribution.StateDependency}},
		admitted: map[string]bool{"saas.example.com": true},
	}
	svc := &Service{attributionGate: gate, logger: logger.NewNop()}

	takeover := testScan("nuclei", "saas.example.com")
	takeover.ScannerConfig = map[string]any{"tags": []any{"takeover"}}
	got, err := svc.resolveScanTargets(context.Background(), takeover)
	if err != nil || len(got.Targets) != 1 || got.Unconfirmed != 0 {
		t.Fatalf("takeover run: %+v %v", got, err)
	}

	ordinary := testScan("nuclei", "saas.example.com")
	ordinary.ScannerConfig = map[string]any{"tags": []any{"cve"}}
	got, err = svc.resolveScanTargets(context.Background(), ordinary)
	if err != nil || len(got.Targets) != 0 || got.Unconfirmed != 1 {
		t.Fatalf("ordinary run: %+v %v", got, err)
	}
}

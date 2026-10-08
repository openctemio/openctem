package scan

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// allProven is an ownership gate that blocks nothing and proves every name.
type allProven struct{ proofGate }

func (allProven) UnverifiedTargets(context.Context, shared.ID, []string) ([]string, error) {
	return nil, nil
}

// tierGate proves the names under verified.example and blocks nothing; the
// ceilings come from stubGate.
type tierGate struct{ stubGate }

func (tierGate) UnverifiedTargets(_ context.Context, _ shared.ID, targets []string) ([]string, error) {
	var out []string
	for _, t := range targets {
		if !strings.Contains(t, "verified.example") {
			out = append(out, t)
		}
	}
	return out, nil
}

func refusalsOf(t *testing.T, err error) []scopedom.Refusal {
	t.Helper()
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "TARGET_OUT_OF_SCOPE" || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want TARGET_OUT_OF_SCOPE", err)
	}
	details, _ := de.Details.(map[string]any)
	rs, ok := details["refused"].([]scopedom.Refusal)
	if !ok {
		t.Fatalf("details = %#v", de.Details)
	}
	return rs
}

func TestProbeTier(t *testing.T) {
	for tool, want := range map[string]scopedom.Tier{
		"subfinder": scopedom.TierPassive, "semgrep": scopedom.TierPassive,
		"nuclei": scopedom.TierActive, "httpx": scopedom.TierActive,
		"zap": scopedom.TierIntrusive, "some-tenant-tool": scopedom.TierActive,
	} {
		if got := ProbeTier(tool); got != want {
			t.Errorf("%s: %s, want %s", tool, got, want)
		}
	}
}

// Scan create and quick scan refuse a target whose entries allow less than
// the scanner probes at, and name the entry to raise (RFC-054 §4.2 step 6).
func TestRefuseTierExceeded(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	gate := &stubGate{ceiling: map[string]scopedom.Tier{"passive-only.example.com": scopedom.TierPassive, "safe.example.com": scopedom.TierActive}}
	svc := &Service{attributionGate: gate, logger: logger.NewNop()}

	err := svc.refuseTierExceeded(ctx, tenant, "nuclei", []string{"ok.example.com", "passive-only.example.com"})
	rs := refusalsOf(t, err)
	if len(rs) != 1 || rs[0].Target != "passive-only.example.com" || rs[0].Code != scopedom.RefusalTierExceeds {
		t.Fatalf("refusals = %+v", rs)
	}
	if f := rs[0].Fixes; len(f) != 1 || f[0].Action != scopedom.FixRaiseTier || f[0].ID != "entry-passive-only.example.com" ||
		f[0].Tier != "t1" || f[0].Requires != "attack_surface:scope:approve" {
		t.Fatalf("fixes = %+v", f)
	}

	// An intrusive scanner needs a t2 entry.
	rs = refusalsOf(t, svc.refuseTierExceeded(ctx, tenant, "zap", []string{"safe.example.com"}))
	if len(rs) != 1 || rs[0].Fixes[0].Tier != "t2" {
		t.Fatalf("zap refusals = %+v", rs)
	}

	// A passive tool, a workflow (no scanner) and an allowed target pass.
	for _, c := range []struct{ scanner, target string }{
		{"subfinder", "passive-only.example.com"},
		{"", "passive-only.example.com"},
		{"nuclei", "safe.example.com"},
	} {
		if err := svc.refuseTierExceeded(ctx, tenant, c.scanner, []string{c.target}); err != nil {
			t.Fatalf("%q on %s: %v", c.scanner, c.target, err)
		}
	}
	// A failed check refuses (fail closed).
	svc.attributionGate = &stubGate{err: errors.New("db down")}
	if err := svc.refuseTierExceeded(ctx, tenant, "nuclei", []string{"ok.example.com"}); err == nil {
		t.Fatal("a failed tier check must refuse")
	}
}

// A run leaves out the targets above their ceiling, says so, and refuses a
// run left with nothing.
func TestResolveScanTargets_TierCeiling(t *testing.T) {
	gate := &stubGate{ceiling: map[string]scopedom.Tier{"passive-only.example.com": scopedom.TierPassive}}
	svc := allowAllChecks(&Service{scopeExclusions: &stubExclusions{}, attributionGate: gate, logger: logger.NewNop()})

	sc := testScan("nuclei", "ok.example.com", "passive-only.example.com")
	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Targets, []string{"ok.example.com"}) || got.TierExceeded != 1 {
		t.Fatalf("targets=%v tierExceeded=%d", got.Targets, got.TierExceeded)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "t1") {
		t.Fatalf("warnings = %v", got.Warnings)
	}
	rc := map[string]any{}
	if err := recordResolvedTargets(sc, got, rc); err != nil || rc["tier_exceeded_target_count"] != 1 {
		t.Fatalf("record: %v %v", err, rc)
	}

	// The same target under a passive scanner is kept.
	if got, err := svc.resolveScanTargets(context.Background(), testScan("subfinder", "passive-only.example.com")); err != nil || len(got.Targets) != 1 {
		t.Fatalf("passive scanner: %+v %v", got, err)
	}

	only := testScan("nuclei", "passive-only.example.com")
	got, err = svc.resolveScanTargets(context.Background(), only)
	if err != nil {
		t.Fatal(err)
	}
	var de *shared.DomainError
	if err := recordResolvedTargets(only, got, map[string]any{}); !errors.As(err, &de) || de.Code != codeTierExceeds {
		t.Fatalf("every target above its ceiling: err = %v, want %s", err, codeTierExceeds)
	}

	svc.attributionGate = &stubGate{err: errors.New("db down")}
	if _, err := svc.resolveScanTargets(context.Background(), sc); err == nil {
		t.Fatal("a failed tier check must stop the run")
	}
}

// The dispatch gate (pipelines/runs, hops, coverage, validation, dry run)
// checks the probe's tier, t1 unless the caller says otherwise; passive
// dispatches are not tier-checked.
func TestResolveDispatchTargets_TierCeiling(t *testing.T) {
	gate := &stubGate{ceiling: map[string]scopedom.Tier{"passive-only.example.com": scopedom.TierPassive, "safe.example.com": scopedom.TierActive}}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: gate, logger: logger.NewNop()}
	targets := []string{"passive-only.example.com", "safe.example.com", "any.example.com"}
	tier := func(t scopedom.Tier) *scopedom.Tier { return &t }

	cases := []struct {
		name    string
		in      DispatchTargetsInput
		refused []string
	}{
		{"default t1", DispatchTargetsInput{}, []string{"passive-only.example.com"}},
		{"t0", DispatchTargetsInput{Tier: tier(scopedom.TierPassive)}, nil},
		{"t2", DispatchTargetsInput{Tier: tier(scopedom.TierIntrusive)}, []string{"passive-only.example.com", "safe.example.com"}},
		{"passive stage", DispatchTargetsInput{PassiveOnly: true, Tier: tier(scopedom.TierIntrusive)}, nil},
	}
	for _, c := range cases {
		in := c.in
		in.TenantID, in.Targets = shared.NewID(), targets
		got, err := svc.ResolveDispatchTargets(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !sameSet(refusedTargets(got), c.refused) {
			t.Fatalf("%s: refused %v, want %v", c.name, got.Refused, c.refused)
		}
		for _, r := range got.Refused {
			if r.Code != scopedom.RefusalTierExceeds {
				t.Fatalf("%s: code %q", c.name, r.Code)
			}
		}
	}
	svc.attributionGate = &stubGate{err: errors.New("db down")}
	if _, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{TenantID: shared.NewID(), Targets: targets}); err == nil {
		t.Fatal("a failed check must refuse the dispatch")
	}
}

// Each workflow step is checked at its own tool's tier, and an intrusive
// step needs proof per step (RFC-054 §8.1): the run's other steps are not
// affected.
func TestFilterStepTargets_TierAndProof(t *testing.T) {
	gate := &tierGate{stubGate{ceiling: map[string]scopedom.Tier{
		"passive-only.verified.example": scopedom.TierPassive,
		"safe.verified.example":         scopedom.TierActive,
	}}}
	svc := &Service{attributionGate: gate, logger: logger.NewNop()}
	rc := map[string]any{"targets": []string{
		"passive-only.verified.example", "safe.verified.example", "t2.verified.example", "unproven.example.com",
	}}
	ctx, tenant := context.Background(), shared.NewID()

	// Passive step: everything.
	st, err := svc.FilterStepTargets(ctx, tenant, "subfinder", rc)
	if err != nil || len(st.Targets) != 4 || st.Refused != 0 {
		t.Fatalf("subfinder: %+v %v", st, err)
	}
	// Active step: the t0-only entry is left out.
	st, err = svc.FilterStepTargets(ctx, tenant, "nuclei", rc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.Targets, []string{"safe.verified.example", "t2.verified.example", "unproven.example.com"}) || st.Refused != 1 ||
		!strings.Contains(st.Reason, "below t1") {
		t.Fatalf("nuclei: %+v", st)
	}
	// Intrusive step: t2 entries only, and proven names only.
	st, err = svc.FilterStepTargets(ctx, tenant, "zap", rc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.Targets, []string{"t2.verified.example"}) || st.Refused != 3 ||
		!strings.Contains(st.Reason, "verified domain") || !strings.Contains(st.Reason, "below t2") {
		t.Fatalf("zap: %+v", st)
	}
	// Nothing left for the intrusive step: it fails, before any sensor.
	_, err = svc.FilterStepTargets(ctx, tenant, "zap", map[string]any{"targets": []string{"unproven.example.com"}})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeStepTargetsRefused || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want %s", err, CodeStepTargetsRefused)
	}
	// Without a proof verifier an intrusive step proves nothing (fail closed).
	plain := &Service{attributionGate: &stubGate{}, logger: logger.NewNop()}
	if _, err := plain.FilterStepTargets(ctx, tenant, "zap", map[string]any{"targets": []string{"t2.verified.example"}}); !errors.As(err, &de) || de.Code != CodeStepTargetsRefused {
		t.Fatalf("no verifier: err = %v", err)
	}
	// A failed tier check fails the step.
	failing := &Service{attributionGate: &stubGate{err: errors.New("db down")}, logger: logger.NewNop()}
	if _, err := failing.FilterStepTargets(ctx, tenant, "nuclei", rc); err == nil {
		t.Fatal("a failed tier check must fail the step")
	}
}

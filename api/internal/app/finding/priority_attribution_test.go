package finding

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type stubAttribution struct {
	states map[string]attribution.State
	err    error
	calls  int
	tenant shared.ID
}

func (s *stubAttribution) ActiveCheckBlocked(_ context.Context, tenantID shared.ID, ids []string) (map[string]attribution.State, error) {
	s.calls++
	s.tenant = tenantID
	out := map[string]attribution.State{}
	for _, id := range ids {
		if st, ok := s.states[id]; ok {
			out[id] = st
		}
	}
	return out, s.err
}

type fixedRuleRepo struct {
	rules []*vulnerability.PriorityOverrideRule
}

func (r fixedRuleRepo) ListActiveByTenant(context.Context, shared.ID) ([]*vulnerability.PriorityOverrideRule, error) {
	return r.rules, nil
}

func classOf(t *testing.T, f *vulnerability.Finding) vulnerability.PriorityClass {
	t.Helper()
	if f.PriorityClass() == nil {
		t.Fatal("finding not classified")
	}
	return *f.PriorityClass()
}

// A P1 finding on an asset waiting for attribution review is capped at P2,
// with the reason; on a confirmed or legacy asset it stays P1.
func TestClassifyFinding_AttributionCap(t *testing.T) {
	tenantID := shared.NewID()
	for state, want := range map[attribution.State]vulnerability.PriorityClass{
		attribution.StateNeedsReview:  vulnerability.PriorityP2,
		attribution.StateCandidate:    vulnerability.PriorityP2,
		attribution.StateRejected:     vulnerability.PriorityP2,
		attribution.StateDependency:   vulnerability.PriorityP1, // a person said the name is ours
		attribution.StateMonitorOnly:  vulnerability.PriorityP1,
		attribution.State("legacy/—"): vulnerability.PriorityP1, // no record
	} {
		f, a := criticalReachableFinding(t, tenantID)
		svc := newControlSvc()
		stub := &stubAttribution{states: map[string]attribution.State{}}
		if state.Valid() {
			stub.states[a.ID().String()] = state
		}
		svc.SetAttributionLookup(stub)
		if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
			t.Fatal(err)
		}
		if got := classOf(t, f); got != want {
			t.Errorf("%s: class %s, want %s (%s)", state, got, want, f.PriorityClassReason())
		}
		capped := strings.Contains(f.PriorityClassReason(), vulnerability.AttributionCapReason)
		if capped != (want == vulnerability.PriorityP2) {
			t.Errorf("%s: cap reason present=%v: %q", state, capped, f.PriorityClassReason())
		}
		if stub.tenant != tenantID {
			t.Errorf("%s: lookup not scoped to the tenant", state)
		}
	}
}

// A tenant override rule cannot page anyone for an unconfirmed asset either.
func TestClassifyFinding_AttributionCapAppliesToRules(t *testing.T) {
	tenantID := shared.NewID()
	f, a := criticalReachableFinding(t, tenantID)
	rule, err := vulnerability.NewPriorityOverrideRule(tenantID, "all critical are P0", vulnerability.PriorityP0,
		[]vulnerability.RuleCondition{{Field: "severity", Operator: "eq", Value: "critical"}}, shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewPriorityClassificationService(nil, nil, nil, nil, fixedRuleRepo{rules: []*vulnerability.PriorityOverrideRule{rule}}, stubAuditRepo{}, logger.NewNop())
	svc.SetAttributionLookup(&stubAttribution{states: map[string]attribution.State{a.ID().String(): attribution.StateNeedsReview}})
	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatal(err)
	}
	if got := classOf(t, f); got != vulnerability.PriorityP2 {
		t.Fatalf("rule result on an unconfirmed asset = %s (%s)", got, f.PriorityClassReason())
	}
	if !strings.Contains(f.PriorityClassReason(), "Rule: all critical are P0") {
		t.Fatalf("reason lost the rule: %q", f.PriorityClassReason())
	}
}

// The batch path (ingest and the reclassify sweep) does one lookup and caps.
func TestEnrichAndClassifyBatch_AttributionCap(t *testing.T) {
	tenantID := shared.NewID()
	f1, a1 := criticalReachableFinding(t, tenantID)
	f2, a2 := criticalReachableFinding(t, tenantID)
	svc := newControlSvc()
	stub := &stubAttribution{states: map[string]attribution.State{a1.ID().String(): attribution.StateCandidate}}
	svc.SetAttributionLookup(stub)
	if err := svc.EnrichAndClassifyBatch(context.Background(), tenantID, []*vulnerability.Finding{f1, f2},
		map[shared.ID]*asset.Asset{a1.ID(): a1, a2.ID(): a2}); err != nil {
		t.Fatal(err)
	}
	if stub.calls != 1 {
		t.Fatalf("batch must look attribution up once, got %d", stub.calls)
	}
	if classOf(t, f1) != vulnerability.PriorityP2 || classOf(t, f2) != vulnerability.PriorityP1 {
		t.Fatalf("batch classes = %s, %s", classOf(t, f1), classOf(t, f2))
	}
}

// A failed lookup keeps the previous behavior (no cap), never fails.
func TestClassifyFinding_AttributionLookupErrorNoCap(t *testing.T) {
	tenantID := shared.NewID()
	f, a := criticalReachableFinding(t, tenantID)
	svc := newControlSvc()
	svc.SetAttributionLookup(&stubAttribution{err: errors.New("db down")})
	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatal(err)
	}
	if classOf(t, f) != vulnerability.PriorityP1 {
		t.Fatalf("lookup error changed the class: %s", classOf(t, f))
	}
}

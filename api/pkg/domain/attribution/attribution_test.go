package attribution

import "testing"

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name   string
		fired  []Rule
		state  State
		conf   int
		reason Rule
	}{
		{"verified root auto-confirms (O4: strong and >= 90)", []Rule{RuleVerifiedRoot}, StateConfirmed, 99, RuleVerifiedRoot},
		{"asserted root alone waits for review", []Rule{RuleAssertedRoot}, StateNeedsReview, 85, RuleAssertedRoot},
		{"a repeated rule is one piece of evidence", []Rule{RuleAssertedRoot, RuleAssertedRoot, RuleAssertedRoot}, StateNeedsReview, 85, RuleAssertedRoot},
		{"asserted root plus tenant scanned confirms", []Rule{RuleAssertedRoot, RuleTenantScanned}, StateConfirmed, 99, RuleTenantScanned},
		{"no evidence is a candidate", nil, StateCandidate, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Evaluate(tc.fired)
			if err != nil {
				t.Fatal(err)
			}
			if d.State != tc.state || d.Confidence != tc.conf || d.Reason != tc.reason {
				t.Fatalf("Evaluate(%v) = %+v, want %s/%d/%s", tc.fired, d, tc.state, tc.conf, tc.reason)
			}
		})
	}
	if _, err := Evaluate([]Rule{"made_up"}); err == nil {
		t.Fatal("unknown rule accepted")
	}
}

// A medium rule never auto-confirms, however high the number: O4 requires a
// strong rule.
func TestEvaluate_MediumNeverAutoConfirms(t *testing.T) {
	saved := rules[RuleAssertedRoot]
	rules[RuleAssertedRoot] = ruleDef{0.97, ClassMedium}
	defer func() { rules[RuleAssertedRoot] = saved }()
	d, _ := Evaluate([]Rule{RuleAssertedRoot})
	if d.State != StateNeedsReview || d.Confidence != 97 {
		t.Fatalf("medium-only evidence at 97 = %+v, want needs_review", d)
	}
}

func TestMerge(t *testing.T) {
	review := Decision{State: StateNeedsReview, Confidence: 85, Reason: RuleAssertedRoot}
	confirm := Decision{State: StateConfirmed, Confidence: 99, Reason: RuleVerifiedRoot}

	if got := Merge(nil, review); got != review {
		t.Errorf("new record = %+v", got)
	}
	// Automation raises.
	if got := Merge(&Record{State: StateNeedsReview, Confidence: 85}, confirm); got.State != StateConfirmed {
		t.Errorf("raise = %+v", got)
	}
	// Automation never lowers.
	if got := Merge(&Record{State: StateConfirmed, Confidence: 99, Reason: RuleVerifiedRoot}, review); got.State != StateConfirmed || got.Confidence != 99 {
		t.Errorf("lowered = %+v", got)
	}
	// A human decision stands, even against strong evidence.
	if got := Merge(&Record{State: StateRejected, HumanDecided: true}, confirm); got.State != StateRejected {
		t.Errorf("human rejection overridden: %+v", got)
	}
}

func TestAllowsActiveChecks(t *testing.T) {
	for s, want := range map[State]bool{
		"": true, StateConfirmed: true,
		StateNeedsReview: false, StateCandidate: false, StateDependency: false, StateMonitorOnly: false, StateRejected: false,
	} {
		if got := s.AllowsActiveChecks(); got != want {
			t.Errorf("%q.AllowsActiveChecks() = %v, want %v", s, got, want)
		}
	}
}

package coverage

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/liveness"
)

// A sensor before sdk-go v0.38.0 refuses a name as unresolvable without
// saying whether its resolver answered "no such name" or the lookup failed
// (a timeout, a SERVFAIL from a resolver under load). Repeated past every
// gone threshold, by two observers, such refusals must leave the name
// without evidence: never gone, so nothing is ever closed by them. The same
// series with an explicit name_gone does reach gone, which proves the test
// measures the DNS kind and not the thresholds.
func TestLiveness_RefusalWithoutDNSKindNeverMovesTowardsGone(t *testing.T) {
	th := liveness.DefaultThresholds()
	guards := liveness.Guards{Known: true, DanglingChecked: true}
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	series := func(dns string) liveness.Evidence {
		e := liveness.Evidence{}
		e = e.Observe(liveness.Observation{Kind: liveness.KindAnswered, Observer: "sensor:a"}, start.Add(-24*time.Hour))
		refused := map[string]any{"target": "old.example.com", "reason": "unresolvable"}
		if dns != "" {
			refused["dns"] = dns
		}
		raw, err := json.Marshal(map[string]any{"metadata": map[string]any{"refused_targets": []any{refused}}})
		if err != nil {
			t.Fatal(err)
		}
		// Twice a day for 14 days, alternating two observers: well past
		// the attempts, the window and the two-observer rule.
		for i := 0; i < 28; i++ {
			v := covdom.Verdicts([]covdom.TaskResult{{Status: "completed", Targets: []string{"old.example.com"}, Result: raw}}, nil)["old.example.com"]
			kind, ok := livenessKind("vuln.templates", v)
			if !ok {
				continue
			}
			observer := fmt.Sprintf("sensor:%c", 'a'+rune(i%2))
			e = e.Observe(liveness.Observation{Kind: kind, Observer: observer, Capability: "vuln.templates", Outcome: v.Outcome},
				start.Add(time.Duration(i)*12*time.Hour))
		}
		return e
	}

	old := series("")
	if old.NXCount != 0 {
		t.Fatalf("a refusal without a DNS kind counted %d NXDOMAIN observations", old.NXCount)
	}
	if s, _ := liveness.Decide(old, guards, th); s == liveness.StateGone {
		t.Fatalf("a name refused without a DNS kind became %s", s)
	}
	if old.NXConfirmed(th) {
		t.Fatal("a refusal without a DNS kind confirmed NXDOMAIN")
	}

	failed := series("resolver_failed")
	if s, _ := liveness.Decide(failed, guards, th); s == liveness.StateGone {
		t.Fatalf("a name whose lookups failed became %s", s)
	}

	gone := series("name_gone")
	if s, _ := liveness.Decide(gone, guards, th); s != liveness.StateGone {
		t.Fatalf("an explicit name_gone series ended %s, want gone (the control case)", s)
	}
}

// An unknown DNS kind neither advances nor resets a streak already under
// way: a name with real NXDOMAIN evidence keeps it.
func TestLiveness_UnknownDNSKindLeavesStreakAsItIs(t *testing.T) {
	v := covdom.Verdict{Kind: covdom.VerdictUnresolved, Outcome: covdom.OutcomeDNSUnknown}
	if k, ok := livenessKind("vuln.templates", v); ok {
		t.Fatalf("unknown DNS kind gave observation %q", k)
	}
	if k, ok := livenessKind(covdom.CapabilityResolveDNS, v); ok {
		t.Fatalf("unknown DNS kind on resolve.dns gave observation %q", k)
	}
}

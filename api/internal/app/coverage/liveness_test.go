package coverage

import (
	"testing"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/liveness"
)

func TestLivenessKind(t *testing.T) {
	cases := []struct {
		name string
		cap  string
		v    covdom.Verdict
		want liveness.Kind
		ok   bool
	}{
		{"probe answered", "probe.http", covdom.Verdict{Kind: covdom.VerdictCovered}, liveness.KindAnswered, true},
		{"templates timed out", "vuln.templates", covdom.Verdict{Kind: covdom.VerdictFailed, Outcome: "timeout"}, liveness.KindNoAnswer, true},
		{"ports unreachable", "scan.ports", covdom.Verdict{Kind: covdom.VerdictFailed, Outcome: "unreachable"}, liveness.KindNoAnswer, true},
		// A WAF or CDN block is an answer: never evidence of absence.
		{"edge blocked", "vuln.templates", covdom.Verdict{Kind: covdom.VerdictFailed, Outcome: "edge_blocked"}, liveness.KindAnswered, true},
		{"edge challenged", "probe.http", covdom.Verdict{Kind: covdom.VerdictFailed, Outcome: "edge_challenged"}, liveness.KindAnswered, true},
		// The tool or the platform failed: nothing about the target.
		{"tool error", "probe.http", covdom.Verdict{Kind: covdom.VerdictFailed, Outcome: "tool_error"}, "", false},
		{"sensor failure", "probe.http", covdom.Verdict{Kind: covdom.VerdictFailed, Outcome: covdom.OutcomeFailed}, "", false},
		{"unfinished", "probe.http", covdom.Verdict{Kind: covdom.VerdictFailed, Outcome: covdom.OutcomeUnfinished}, "", false},
		{"blocked by policy", "probe.http", covdom.Verdict{Kind: covdom.VerdictBlocked, Reason: "refused"}, "", false},
		{"dns resolved", "resolve.dns", covdom.Verdict{Kind: covdom.VerdictCovered}, liveness.KindResolved, true},
		{"nxdomain", "resolve.dns", covdom.Verdict{Kind: covdom.VerdictUnresolved, Outcome: covdom.OutcomeNoAnswer}, liveness.KindNXDomain, true},
		{"refused unresolvable", "vuln.templates", covdom.Verdict{Kind: covdom.VerdictUnresolved, Outcome: covdom.OutcomeNoAnswer}, liveness.KindNXDomain, true},
		{"servfail", "vuln.templates", covdom.Verdict{Kind: covdom.VerdictUnresolved, Outcome: covdom.ReasonResolverFailed}, liveness.KindResolverFailed, true},
		// A sensor that does not say why the name did not resolve: no
		// evidence, never NXDOMAIN.
		{"unknown dns kind", "vuln.templates", covdom.Verdict{Kind: covdom.VerdictUnresolved, Outcome: covdom.OutcomeDNSUnknown}, "", false},
		{"unknown dns kind on resolve.dns", "resolve.dns", covdom.Verdict{Kind: covdom.VerdictUnresolved, Outcome: covdom.OutcomeDNSUnknown}, "", false},
		// Passive lookups say nothing about whether the asset answers.
		{"rdap", "lookup.rdap", covdom.Verdict{Kind: covdom.VerdictCovered}, "", false},
		{"enumerate", "enumerate.subdomains", covdom.Verdict{Kind: covdom.VerdictFailed, Outcome: "timeout"}, "", false},
	}
	for _, c := range cases {
		got, ok := livenessKind(c.cap, c.v)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: %q/%v, want %q/%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

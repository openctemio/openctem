package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A finding of the organization's own rules is recorded even without a
// template digest: by the sensor's mark or the tenant: rule id prefix.
func TestFindingTemplateProvenanceRuleSource(t *testing.T) {
	cases := []struct {
		name   string
		f      ctis.Finding
		source string
		ruleID string
		empty  bool
	}{
		{"marked nuclei", ctis.Finding{RuleID: "tenant:login", Properties: ctis.Properties{"rule_source": "tenant"}}, "tenant", "login", false},
		{"prefixed semgrep, no properties", ctis.Finding{RuleID: "tenant:weak-hash"}, "tenant", "weak-hash", false},
		{"platform without digest", ctis.Finding{RuleID: "weak-hash"}, "", "", true},
		{"platform claim ignored", ctis.Finding{RuleID: "x", Properties: ctis.Properties{"rule_source": "platform"}}, "", "", true},
	}
	for _, c := range cases {
		p := findingTemplateProvenance(&c.f, nil)
		if p.RuleSource != c.source || p.RuleID != c.ruleID || p.Empty() != c.empty {
			t.Errorf("%s: provenance = %+v (empty %v)", c.name, p, p.Empty())
		}
	}
	if p := findingTemplateProvenance(nil, nil); p != (vulnerability.TemplateProvenance{}) {
		t.Errorf("nil finding = %+v", p)
	}
}

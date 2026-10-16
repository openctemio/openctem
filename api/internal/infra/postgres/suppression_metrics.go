package postgres

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// suppressionRuleHits counts the findings an approved suppression rule
// decided, by how: "ingest" (a new finding a rule matched as it arrived) and
// "approval" (an open finding the rule closed when it was approved). A
// finding already linked to the rule is not counted again. The labels are a
// closed set: no tenant, rule or finding id, so the series count stays
// bounded; the per-rule and per-tenant breakdown is finding_suppressions.
var suppressionRuleHits = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "openctem",
	Subsystem: "suppression",
	Name:      "rule_hits_total",
	Help:      "Findings decided by an approved suppression rule, by how the rule applied (ingest, approval, other).",
}, []string{"applied_by"})

// Values of the applied_by label of suppressionRuleHits.
const (
	suppressionHitIngest   = "ingest"
	suppressionHitApproval = "approval"
	suppressionHitOther    = "other"
)

// observeSuppressionHits adds n hits under the label for the applied_by value
// stored on finding_suppressions ("system" is ingest, "approval" the
// approval). Any other value is counted as "other" so the label set stays
// closed.
func observeSuppressionHits(appliedBy string, n int) {
	if n <= 0 {
		return
	}
	label := suppressionHitOther
	switch appliedBy {
	case "system":
		label = suppressionHitIngest
	case "approval":
		label = suppressionHitApproval
	}
	suppressionRuleHits.WithLabelValues(label).Add(float64(n))
}

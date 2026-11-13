package querylang

import (
	"strings"
	"testing"
)

// The practice and compliance_result fields are part of the query language:
// filters on them compile, both can be grouped, and an unknown practice is
// refused with its position.
func TestPracticeQueries(t *testing.T) {
	for _, src := range []string{
		"findings where practice = compliance and compliance_result = fail",
		"findings where practice != compliance | count by practice",
		"findings where practice in (aspm, infra) | count by practice, severity",
		"findings where practice = compliance | count by compliance_result",
	} {
		mustBuild(t, src, memberAll())
	}
	_, err := build(t, "findings where practice = vulnerabilities", memberAll())
	if err == nil || !strings.Contains(err.Error(), "1:27") || !strings.Contains(err.Error(), "compliance") {
		t.Fatalf("unknown practice: %v", err)
	}
}

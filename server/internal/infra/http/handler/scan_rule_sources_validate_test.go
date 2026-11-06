package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/validator"
)

// The edit dialog sends back the scan's own rule_sources, which is "" when
// the scan inherits its profile's. That must pass request validation; bad
// values are rejected by the domain setter instead.
func TestUpdateScanRequest_RuleSourcesInheritAccepted(t *testing.T) {
	v := validator.New()
	for _, val := range []string{"", "both", "platform", "tenant", "everything"} {
		val := val
		req := UpdateScanRequest{RuleSources: &val}
		if err := v.Validate(req); err != nil {
			t.Fatalf("rule_sources %q: request validation should defer to the domain, got %v", val, err)
		}
	}
}

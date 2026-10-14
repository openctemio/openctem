package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Coverage never starts an intrusive capability, an unknown one, an empty
// or oversized batch: refused before any target is looked at.
func TestStartCoverage_RefusesBeforeTheGate(t *testing.T) {
	s := &Service{}
	tenant := shared.NewID()
	big := make([]string, maxCoverageTargets+1)
	for i := range big {
		big[i] = "x.example.com"
	}
	for name, in := range map[string]CoverageInput{
		"intrusive": {TenantID: tenant, Capability: "dast.web", Targets: []string{"https://a.example.com"}},
		"unknown":   {TenantID: tenant, Capability: "probe.everything", Targets: []string{"a.example.com"}},
		"no tenant": {Capability: "probe.http", Targets: []string{"a.example.com"}},
		"empty":     {TenantID: tenant, Capability: "probe.http"},
		"oversized": {TenantID: tenant, Capability: "probe.http", Targets: big},
	} {
		if _, err := s.StartCoverage(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
	if CoverageScanName("probe.http") != "Continuous coverage: probe.http" {
		t.Error("coverage scan name changed")
	}
}

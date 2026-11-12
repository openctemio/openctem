package ingest

// The capability a command-bound report answers, and its required output
// (OpenCTEM Tool Contract v1, docs/rfcs/RFC-055-tool-contract-v1.md).
//
// A report's metadata.capability is a sensor claim (CTIS 1.5). The platform
// derives the capability from the command's tool instead: the capabilities
// its tool implements, from the catalog (built-in tools) and from the
// tool's declared contract in its sensor's manifest. The claim is kept only
// when it names one of those; with one candidate the candidate is used; with
// none or several and no matching claim the capability is cleared. Ingest
// then keys capability-specific handling on it (port-closure reconciliation
// for scan.ports) and checks the capability's required CTIS output: a
// report that misses it is logged and counted (warn, decision TC13; it is
// applied as before).

import (
	"context"
	"encoding/json"

	"fmt"
	"slices"

	"github.com/openctemio/contract/capability"
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/metrics"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
)

// maxContractViolationsLogged bounds the violations one log line names.
const maxContractViolationsLogged = 5

// candidateCapabilities are the capability references a report of the
// tool may answer: its catalog stages and its declared implements.
func candidateCapabilities(rules outputRules) []string {
	var out []string
	for _, st := range rules.stages {
		ref := fmt.Sprintf("%s@%d", st.Key, stage.ContractVersion)
		if _, ok := capability.Lookup(ref); ok && !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	if rules.declared != nil {
		for _, ref := range rules.declared.Implements {
			if !slices.Contains(out, ref) {
				out = append(out, ref)
			}
		}
	}
	return out
}

// boundCapability is the capability the platform binds the report to.
func boundCapability(rules outputRules, claimed, tool string) string {
	cands := candidateCapabilities(rules)
	if claimed != "" && slices.Contains(cands, claimed) {
		return claimed
	}
	if len(cands) == 1 {
		return cands[0]
	}
	// A tool with several stages, one of them run only when a job names it
	// (naabu: host discovery): a report that names none is the tool's own
	// stage (naabu: a port scan).
	if st, ok := stage.ForStep(tool, nil); ok {
		if ref := fmt.Sprintf("%s@%d", st.Key, stage.ContractVersion); slices.Contains(cands, ref) {
			return ref
		}
	}
	return ""
}

// checkCapabilityContract logs and counts a report that misses the required
// output of its capability. It never changes the report.
func (s *Service) checkCapabilityContract(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, tool string, report *ctis.Report) {
	ref := reportCapability(report)
	if ref == "" {
		return
	}
	c, ok := capability.Lookup(ref)
	if !ok {
		return
	}
	doc, err := reportJSONMap(report)
	if err != nil {
		return
	}
	violations, err := c.Check(doc, capability.CheckOptions{})
	if err != nil || len(violations) == 0 {
		return
	}
	shown := make([]string, 0, maxContractViolationsLogged)
	for _, v := range violations[:min(len(violations), maxContractViolationsLogged)] {
		shown = append(shown, sanitizeIngestLogField(v.String()))
	}
	metrics.SensorUnsolicitedResultsTotal.WithLabelValues("capability_contract_warned").Inc()
	s.logger.Warn("sensor report misses the output contract of its capability; applied (warn)",
		"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "tool", sanitizeIngestLogField(tool),
		"capability", sanitizeIngestLogField(ref), "violations", len(violations), "first", shown,
		"report_id", reportIDOf(ctx))
}

// reportJSONMap is the decoded JSON form of a report, what the contract
// module's checks read (they take no CTIS Go types).
func reportJSONMap(report *ctis.Report) (map[string]any, error) {
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

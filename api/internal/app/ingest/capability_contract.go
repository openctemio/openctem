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
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
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
	if st, ok := primaryStage(rules.stages, tool); ok {
		if ref := fmt.Sprintf("%s@%d", st.Key, stage.ContractVersion); slices.Contains(cands, ref) {
			return ref
		}
	}
	return ""
}

// primaryStage is the one stage among the tool's stages that it runs
// without a job naming the capability (its contract's primary capability).
func primaryStage(stages []stage.Stage, tool string) (stage.Stage, bool) {
	var out []stage.Stage
	for _, st := range stages {
		for _, im := range st.Implementations {
			if strings.EqualFold(im.Tool, strings.TrimSpace(tool)) && !im.ByCapability {
				out = append(out, st)
			}
		}
	}
	if len(out) != 1 {
		return stage.Stage{}, false
	}
	return out[0], true
}

// checkCapabilityContract logs and counts a report that misses the required
// output of its capability. It never changes the report.
func (s *Service) checkCapabilityContract(agt *sensor.Sensor, tenantID shared.ID, tool string, report *ctis.Report) {
	ref := report.Metadata.Capability
	if ref == "" {
		return
	}
	c, ok := capability.Lookup(ref)
	if !ok {
		return
	}
	violations, err := c.Check(report, capability.CheckOptions{})
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
		"report_id", sanitizeIngestLogField(report.Metadata.ID))
}

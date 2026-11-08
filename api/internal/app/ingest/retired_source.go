package ingest

// Reports of a retired source (docs/architecture/source-retirement.md).

import (
	"context"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sourceretire"
)

// refuseRetiredSource refuses a report of a source the tenant stopped
// using: its receipt counts the findings it sent as source_retired, and
// nothing else of it is applied. It reports whether the report was refused.
func (s *Service) refuseRetiredSource(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding,
	opts Options, reportID string, report *ctis.Report, output *Output,
) bool {
	if output.policy == nil || len(output.policy.Retired) == 0 {
		return false
	}
	tool := ""
	if report.Tool != nil {
		tool = report.Tool.Name
	}
	src := receiptSource(agt, binding, opts, reportID)
	rep := sourceretire.Report{
		Channel:  ingestreceipt.ChannelOf(src.Kind),
		Instance: receiptInstance(agt, binding, opts, report),
		Tool:     tool,
	}
	if !output.policy.retiredSource(rep) {
		return false
	}
	output.addOutcome(ingestreceipt.OutcomeSourceRetired, len(report.Findings))
	output.SourceRetired = true
	s.logger.Info("ingest: report of a retired source refused",
		"tenant_id", tenantID.String(), "report_id", reportID, "channel", string(rep.Channel),
		"tool_name", sanitizeIngestLogField(tool), "findings", len(report.Findings), "assets", len(report.Assets))
	// The receipt names the tool of the report, nothing it carried.
	refused := &ctis.Report{Tool: report.Tool, Metadata: report.Metadata}
	s.recordReceipt(ctx, agt, tenantID, binding, opts, refused, output)
	return true
}

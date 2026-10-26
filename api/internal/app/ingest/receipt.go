package ingest

// Receipts: what each ingest and each coverage decision did to the tenant's
// findings (docs/rfcs/RFC-122-ingest-receipts.md). Every ingest is recorded
// on the receipt of the upload or run it belongs to; a coverage decision
// adds the findings it closed and what it left untouched. A receipt never
// decides anything: findings are closed only by the coverage rules
// (coverage_autoresolve.go) or by a source's own mitigation statement
// (source_resolve.go), never because a partial report left them out.

import (
	"context"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ReceiptRecorder writes receipt deltas (ingestreceipt.Repository).
type ReceiptRecorder interface {
	Record(ctx context.Context, d *ingestreceipt.Delta) (shared.ID, error)
}

// SetReceiptRecorder enables receipts.
func (s *Service) SetReceiptRecorder(r ReceiptRecorder) { s.receipts = r }

// coverageUntouchedRepo is implemented by the postgres finding repository.
type coverageUntouchedRepo interface {
	CoverageUntouched(ctx context.Context, tenantID shared.ID, q ingestreport.CoverageQuery, repo bool) (int, error)
}

// receiptSource is the receipt an ingest counts toward.
func receiptSource(agt *sensor.Sensor, binding Binding, opts Options, report *ctis.Report) ingestreceipt.Source {
	if opts.Receipt != nil {
		return *opts.Receipt
	}
	reportID := ""
	if report != nil {
		reportID = report.Metadata.ID
	}
	switch binding.Kind {
	case BindingCommand:
		if binding.CommandID != nil {
			id := *binding.CommandID
			return ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &id}
		}
	case BindingCIRun:
		if binding.CIRunID != nil {
			return ingestreceipt.Source{Kind: ingestreceipt.SourceCIRun, Ref: binding.CIRunID.String()}
		}
	case BindingTrusted:
		ref := opts.SourceRun
		if ref == "" {
			ref = reportID
		}
		if ref == "" || len(ref) > 128 {
			ref = ingestreceipt.ReportRef(shared.ID{}, ref)
		}
		return ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: ref}
	}
	sensorID := shared.ID{}
	if agt != nil {
		sensorID = agt.ID
	}
	if reportID == "" {
		// A report without an id is its own receipt.
		reportID = shared.NewID().String()
	}
	return ingestreceipt.Source{Kind: ingestreceipt.SourceSensor, Ref: ingestreceipt.ReportRef(sensorID, reportID)}
}

// recordReceipt adds what this ingest did to its receipt. The findings are
// already stored, so a failure is logged, counted and flagged on the output
// (ReceiptFailed): the ingest stands, but a command-bound segment is retried
// (IngestV2Segment), because its receipt decides what the run did not report.
func (s *Service) recordReceipt(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding,
	opts Options, report *ctis.Report, output *Output) {
	if s.receipts == nil || output == nil {
		return
	}
	d := &ingestreceipt.Delta{
		TenantID:      tenantID,
		Source:        receiptSource(agt, binding, opts, report),
		Reports:       1,
		AssetsCreated: output.AssetsCreated,
		AssetsUpdated: output.AssetsUpdated,
		Failed:        len(output.FailedFindings),
		Suppressed:    output.FindingsSuppressed,
		Created:       output.CreatedIDs,
		Reopened:      output.ReopenedIDs,
		StillDetected: output.SightedFingerprints,
		Decided:       output.Decided,
		Items:         output.Items,
		At:            time.Now(),
	}
	if report != nil {
		d.Received = len(report.Findings)
		if report.Tool != nil {
			d.Tool = report.Tool.Name
		}
	}
	// Skipped counts the findings not stored for a reason (scope,
	// exclusion, invalid); the ones that failed to store are Failed.
	d.Skipped = max(output.FindingsSkipped-d.Failed, 0)
	if output.SourceResolveMode == SourceResolveEnforce {
		d.Closed = output.SourceResolveIDs
	}
	for _, ff := range output.FailedFindings {
		if len(d.Errors) >= ingestreceipt.MaxErrors {
			break
		}
		d.Errors = append(d.Errors, ingestreceipt.ErrorEntry{Index: ff.Index, Code: ingestreceipt.ErrorStoreFailed})
	}
	id, err := s.receipts.Record(ctx, d)
	if err != nil {
		output.ReceiptFailed = true
		metrics.IngestReceiptWriteFailures.WithLabelValues("ingest").Inc()
		s.logger.Warn("ingest receipt not recorded", "tenant_id", tenantID.String(),
			"source_kind", string(d.Source.Kind), "error", logger.SanitizeError(err))
		return
	}
	output.ReceiptID = id.String()
}

// recordCoverageReceipt adds a coverage decision of a command to its
// receipt: the findings it closed and the open findings of the covered
// scope it left untouched. Only an eligible decision (a covered scan of an
// explicit scope) is recorded; anything else proved no coverage.
func (s *Service) recordCoverageReceipt(ctx context.Context, tenantID, commandID shared.ID, q ingestreport.CoverageQuery,
	out CoverageOutcome, repo bool) {
	if s.receipts == nil || out.Reason != coverageEligible {
		return
	}
	note := "resolved"
	switch {
	case out.Held:
		note = "held"
	case out.Mode == CoverageAutoResolveDryRun:
		note = "dry_run"
	}
	cmd := commandID
	d := &ingestreceipt.Delta{
		TenantID:     tenantID,
		Source:       ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &cmd},
		Tool:         q.ToolName,
		Closed:       out.Resolved,
		Coverage:     ingestreceipt.CoverageFull,
		CoverageNote: note,
		At:           time.Now(),
	}
	if ur, ok := s.findingRepo.(coverageUntouchedRepo); ok {
		n, err := ur.CoverageUntouched(ctx, tenantID, q, repo)
		if err != nil {
			s.logger.Warn("coverage receipt: untouched count failed", "command_id", commandID.String(), "error", logger.SanitizeError(err))
		} else {
			d.Untouched = &n
		}
	}
	if _, err := s.receipts.Record(ctx, d); err != nil {
		metrics.IngestReceiptWriteFailures.WithLabelValues("coverage").Inc()
		s.logger.Warn("coverage receipt not recorded", "tenant_id", tenantID.String(),
			"command_id", commandID.String(), "error", logger.SanitizeError(err))
	}
}

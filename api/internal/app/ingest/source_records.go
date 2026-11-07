package ingest

// Per-source records of findings: what each source reported, kept per source
// so a second source never overwrites the first one's values
// (docs/architecture/finding-source-records.md).

import (
	"context"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// sourceRecordWriter stores per-source records (postgres.FindingRepository).
// Optional: a repository without it keeps none.
type sourceRecordWriter interface {
	UpsertSourceRecords(ctx context.Context, tenantID shared.ID, src vulnerability.SourceIdentity,
		values []vulnerability.SourceRecordValues) (int64, error)
}

// sourceIdentity is the source of an ingest, the same one its sightings
// are recorded under: the receipt channel, the sending instance and the tool.
func sourceIdentity(agt *sensor.Sensor, binding Binding, opts Options, report *ctis.Report) vulnerability.SourceIdentity {
	src := receiptSource(agt, binding, opts, "-")
	inst := receiptInstance(agt, binding, opts, report)
	id := vulnerability.SourceIdentity{Channel: string(ingestreceipt.ChannelOf(src.Kind))}
	switch inst.Kind {
	case ingestreceipt.InstanceSensor:
		id.IsSensor = true
		if sid, err := shared.IDFromString(inst.ID); err == nil && !sid.IsZero() {
			id.SensorID = &sid
		}
	case ingestreceipt.InstanceCI, ingestreceipt.InstanceConnector:
		id.Sender = inst.ID
	}
	if report != nil && report.Tool != nil {
		id.Tool = report.Tool.Name
	}
	return id
}

// storeSourceRecords writes what this ingest's source reported for each
// stored or re-sighted finding. Best effort: the findings are stored, so a
// failure is logged and never fails the ingest.
func (s *Service) storeSourceRecords(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding,
	opts Options, report *ctis.Report, output *Output) {
	if output == nil || len(output.SourceRecords) == 0 || s.findingProcessor == nil {
		return
	}
	w, ok := s.findingProcessor.repo.(sourceRecordWriter)
	if !ok {
		return
	}
	src := sourceIdentity(agt, binding, opts, report)
	if _, err := w.UpsertSourceRecords(ctx, tenantID, src, output.SourceRecords); err != nil {
		s.logger.Warn("finding source records not stored", "tenant_id", tenantID.String(),
			"channel", src.Channel, "count", len(output.SourceRecords), "error", logger.SanitizeError(err))
	}
}

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

// sightingDataWriter stores a batch's interop data and its source's
// per-finding records in one statement (postgres.FindingRepository).
// Optional: a repository without it stores the interop data alone
// (interopWriter) and keeps no source records.
type sightingDataWriter interface {
	StoreSightingData(ctx context.Context, tenantID shared.ID, interop []vulnerability.InteropUpdate,
		src vulnerability.SourceIdentity, records []vulnerability.SourceRecordValues) error
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

// storeSightingData writes the batch's interop data and what this ingest's
// source reported for each stored or re-sighted finding. Best effort: the
// findings are stored, so a failure is logged and never fails the ingest.
// A source without a channel (ProcessBatch outside an ingest) keeps no
// records.
func (p *FindingProcessor) storeSightingData(ctx context.Context, tenantID shared.ID,
	interop []vulnerability.InteropUpdate, src vulnerability.SourceIdentity, records []vulnerability.SourceRecordValues) {
	w, ok := p.repo.(sightingDataWriter)
	if !ok || src.Channel == "" || len(records) == 0 {
		p.storeInterop(ctx, tenantID, interop)
		return
	}
	if err := w.StoreSightingData(ctx, tenantID, interop, src, records); err != nil {
		p.logger.Warn("finding interop data or source records not stored", "tenant_id", tenantID.String(),
			"channel", src.Channel, "interop", len(interop), "records", len(records), "error", logger.SanitizeError(err))
	}
}

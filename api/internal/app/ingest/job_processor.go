package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// ctisIngestEnvelope is the wrapped ingest payload shape: { "report": { ... } }.
type ctisIngestEnvelope struct {
	Report ctis.Report `json:"report"`
}

// ParseReport decodes a raw ingest body into a CTIS report. It accepts both the
// wrapped form ({"report": {...}}) and the flat SDK form ({"version": ...}),
// rejecting unknown fields so a sensor cannot smuggle extra keys. This is the
// single parser shared by the synchronous accept handler and the async worker.
func ParseReport(body []byte) (*ctis.Report, error) {
	// Wrapped form first.
	var env ctisIngestEnvelope
	wrapped := json.NewDecoder(bytes.NewReader(body))
	wrapped.DisallowUnknownFields()
	if err := wrapped.Decode(&env); err == nil && env.Report.Version != "" {
		report := env.Report
		return &report, nil
	}

	// Flat form.
	var report ctis.Report
	flat := json.NewDecoder(bytes.NewReader(body))
	flat.DisallowUnknownFields()
	if err := flat.Decode(&report); err != nil {
		return nil, fmt.Errorf("invalid CTIS payload: %w", err)
	}
	return &report, nil
}

// JobResult is the compact counts summary stored on a completed ingest job.
type JobResult struct {
	ReportID        string `json:"report_id"`
	AssetsCreated   int    `json:"assets_created"`
	AssetsUpdated   int    `json:"assets_updated"`
	FindingsCreated int    `json:"findings_created"`
	FindingsUpdated int    `json:"findings_updated"`
	FindingsSkipped int    `json:"findings_skipped"`
	CVEsCreated     int    `json:"cves_created"`
	CVEsUpdated     int    `json:"cves_updated"`
}

// ingester is the slice of *Service the job processor needs (kept small so the
// processor is unit-testable with a stub).
type ingester interface {
	Ingest(ctx context.Context, agt *sensor.Sensor, input Input) (*Output, error)
}

// JobProcessor turns a queued raw payload back into a CTIS report and runs it
// through the normal ingest pipeline. Used by the async worker (RFC-005).
type JobProcessor struct {
	service ingester
	// sensors re-reads the submitting sensor before a queued report is
	// processed; nil refuses every job (fail closed).
	sensors queuedSensorChecker
	// v2 processes protocol v2 results jobs (RFC-026). Nil when v2 results
	// are disabled; a v2 job then fails and is retried until it is enabled.
	v2 *V2JobProcessor
}

// SetV2 enables processing of protocol v2 results jobs.
func (p *JobProcessor) SetV2(v2 *V2JobProcessor) { p.v2 = v2 }

// Housekeep runs the periodic v2 report expiry. No-op without v2.
func (p *JobProcessor) Housekeep(ctx context.Context) {
	if p.v2 != nil {
		p.v2.Housekeep(ctx)
	}
}

// NewJobProcessor wires a processor over the ingest service.
func NewJobProcessor(service *Service) *JobProcessor {
	return &JobProcessor{service: service, sensors: service}
}

// Process parses the job payload, re-reads the sensor that submitted it and
// ingests it as that sensor. The sensor was authenticated when the job was
// accepted, but it may have been revoked, disabled or deleted while the job
// waited in the queue (RFC-040 §5.2): its work is then dropped, recorded in
// the audit log, and the job completes without being retried. Returns the
// marshaled counts (or the drop) to store on the completed job.
func (p *JobProcessor) Process(ctx context.Context, job *ingestjob.Job) ([]byte, error) {
	if job.V2() != nil {
		if p.v2 == nil {
			return nil, errors.New("protocol v2 results job, but v2 results are disabled")
		}
		return p.v2.Process(ctx, job)
	}
	report, err := ParseReport(job.Payload())
	if err != nil {
		return nil, err
	}
	if report.Version == "" {
		report.Version = "1.0"
	}

	if p.sensors == nil {
		return nil, errors.New("ingest worker: sensor status check is not configured")
	}
	agt, dropped, err := p.sensors.QueuedWorkSensor(ctx, job.TenantID(), job.SensorID(), job.ReportID())
	if err != nil {
		return nil, err
	}
	if dropped != nil {
		return json.Marshal(dropped)
	}

	// The accept side (IngestHandler.enqueueAsync) ran the unsolicited gate
	// before queuing; a v1 report bound to a command is never queued (it is
	// processed synchronously), so a queued report applies with the
	// unsolicited limits.
	output, err := p.service.Ingest(ctx, agt, Input{Report: report, Options: Options{Admitted: true, Route: "ctis"}})
	if err != nil {
		return nil, err
	}

	result := JobResult{
		ReportID:        output.ReportID,
		AssetsCreated:   output.AssetsCreated,
		AssetsUpdated:   output.AssetsUpdated,
		FindingsCreated: output.FindingsCreated,
		FindingsUpdated: output.FindingsUpdated,
		FindingsSkipped: output.FindingsSkipped,
		CVEsCreated:     output.CVEsCreated,
		CVEsUpdated:     output.CVEsUpdated,
	}
	return json.Marshal(result)
}

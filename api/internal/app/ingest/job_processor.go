package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
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
	// kinds process the upload jobs (CI results, file imports) by kind.
	kinds map[ingestjob.Kind]KindProcessor
	// sealer opens sealed protocol v1 jobs and seals, in place, the sensor
	// payloads still queued in plaintext (see SetPayloadSealer).
	sealer    *ingestpayload.Sealer
	plain     PlaintextSealer
	lastSeal  time.Time
	sealLog   *logger.Logger
	sealClock func() time.Time
}

// KindProcessor applies the jobs of one upload kind (a CI run's results, a
// file import) and is told when one failed for good.
type KindProcessor interface {
	Process(ctx context.Context, job *ingestjob.Job) ([]byte, error)
	DeadLetter(ctx context.Context, job *ingestjob.Job, publicErr string)
}

// KindFuncs adapts two functions to a KindProcessor.
type KindFuncs struct {
	ProcessFn    func(ctx context.Context, job *ingestjob.Job) ([]byte, error)
	DeadLetterFn func(ctx context.Context, job *ingestjob.Job, publicErr string)
}

// Process implements KindProcessor.
func (k KindFuncs) Process(ctx context.Context, job *ingestjob.Job) ([]byte, error) {
	return k.ProcessFn(ctx, job)
}

// DeadLetter implements KindProcessor.
func (k KindFuncs) DeadLetter(ctx context.Context, job *ingestjob.Job, publicErr string) {
	if k.DeadLetterFn != nil {
		k.DeadLetterFn(ctx, job, publicErr)
	}
}

// SetKind routes the jobs of kind to p.
func (p *JobProcessor) SetKind(kind ingestjob.Kind, kp KindProcessor) {
	if p.kinds == nil {
		p.kinds = map[ingestjob.Kind]KindProcessor{}
	}
	p.kinds[kind] = kp
}

// DeadLetter tells the job's kind processor that it failed for good.
func (p *JobProcessor) DeadLetter(ctx context.Context, job *ingestjob.Job, publicErr string) {
	if kp := p.kinds[job.Kind()]; kp != nil {
		kp.DeadLetter(ctx, job, publicErr)
	}
}

// SetPayloadSealer sets the sealer queued sensor payloads are opened with
// and, with repo (the job repository), the sealer of those still queued in
// plaintext: Housekeep seals them in place, protocol v1 jobs and v2
// segments alike, so no tenant data waits in plaintext in ingest_jobs.
func (p *JobProcessor) SetPayloadSealer(s *ingestpayload.Sealer, repo PlaintextSealer, log *logger.Logger) {
	if log == nil {
		log = logger.NewNop()
	}
	p.sealer, p.plain, p.sealLog = s, repo, log.With("component", "ingest")
}

// SetV2 enables processing of protocol v2 results jobs.
func (p *JobProcessor) SetV2(v2 *V2JobProcessor) { p.v2 = v2 }

// Housekeep runs the periodic v2 report expiry (when v2 is enabled) and the
// in-place sealing of queued sensor payloads stored in plaintext, batched
// (rows and bytes) and idempotent, safe on several replicas.
func (p *JobProcessor) Housekeep(ctx context.Context) {
	if p.v2 != nil {
		p.v2.Housekeep(ctx)
	}
	p.sealPlaintext(ctx)
}

// sealPlaintext seals the plaintext payloads queued before sealPlaintextAge
// ago (leaving alone one queued moments ago by a replica of the previous
// release: a worker is likely applying it right now), at most every
// stagingPurgeEvery.
func (p *JobProcessor) sealPlaintext(ctx context.Context) {
	if p.plain == nil || p.sealer == nil {
		return
	}
	now := time.Now
	if p.sealClock != nil {
		now = p.sealClock
	}
	t := now()
	if !p.lastSeal.IsZero() && t.Sub(p.lastSeal) < stagingPurgeEvery {
		return
	}
	p.lastSeal = t
	total, err := sealPlaintextSensorPayloads(ctx, p.sealer, p.plain, t.Add(-sealPlaintextAge), p.sealLog)
	if err != nil {
		p.sealLog.Warn("ingest: sealing plaintext queued payloads failed", "error", err)
	}
	if total > 0 {
		p.sealLog.Info("ingest: sealed plaintext queued payloads", "count", total)
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
	if k := job.Kind(); k != ingestjob.KindSensor {
		kp := p.kinds[k]
		if kp == nil {
			// Not wired in this process (yet): retried, then dead.
			return nil, fmt.Errorf("no processor for %s jobs", k)
		}
		return kp.Process(ctx, job)
	}
	if job.V2() != nil {
		if p.v2 == nil {
			return nil, errors.New("protocol v2 results job, but v2 results are disabled")
		}
		return p.v2.Process(ctx, job)
	}
	body, err := openSegment(p.sealer, job)
	if err != nil {
		if errors.Is(err, errNoSegmentSealer) {
			// A configuration gap, not a bad job: retried.
			return nil, err
		}
		// Sealed under a key the server no longer has, or altered at rest:
		// retrying cannot open it.
		return nil, ingestjob.Permanent(ingestjob.ErrorApplyFailed, errors.New("the stored report does not open"))
	}
	report, err := ParseReport(body)
	if err != nil {
		return nil, err
	}
	if report.Version == "" {
		report.Version = "1.0"
	}

	if p.sensors == nil {
		return nil, errors.New("ingest worker: sensor status check is not configured")
	}
	agt, dropped, err := p.sensors.QueuedWorkSensor(ctx, job.TenantID(), job.SensorID(), nil, nil, job.ReportID())
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

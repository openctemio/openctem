package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// V2JobProcessor processes the protocol v2 jobs of the RFC-005 queue: one job
// per segment and one per commit. A segment job ingests its segment and
// records the outcome under its segment number; whichever job sees the
// committed report complete (the last segment or the commit itself) claims
// the finalization, which runs exactly once.
type V2JobProcessor struct {
	service *Service
	sensors queuedSensorChecker // nil refuses every job (fail closed)
	reports ingestreport.Repository
	jobs    ingestjob.V2Repository
	limits  protov2.Limits
	guard   BlindingGuard
	logger  *logger.Logger
	now     func() time.Time
	// lastPurge is when Housekeep last purged the staging tables.
	lastPurge time.Time
}

// Staging retention: what a report that will never be applied may keep.
// Variables so a test can change them.
var (
	// StagingRetention is how long failed and expired reports, and finished
	// jobs without a report, are kept (for the sensor's status reads and
	// for diagnosis) before they are deleted.
	StagingRetention = 7 * 24 * time.Hour
	// stagingPurgeEvery is how often Housekeep purges (it runs every drain
	// cycle).
	stagingPurgeEvery = 10 * time.Minute
	// stagingPurgeBatch caps the rows one purge step touches.
	stagingPurgeBatch = 5000
)

// stagingPurger is implemented by the postgres report repository.
type stagingPurger interface {
	PurgeStaging(ctx context.Context, before time.Time, batch int) (ingestreport.StagingPurge, error)
}

// NewV2JobProcessor wires the v2 job processor.
func NewV2JobProcessor(svc *Service, reports ingestreport.Repository, jobs ingestjob.V2Repository, limits protov2.Limits, guard BlindingGuard, log *logger.Logger) *V2JobProcessor {
	if log == nil {
		log = logger.NewNop()
	}
	return &V2JobProcessor{service: svc, sensors: svc, reports: reports, jobs: jobs, limits: limits, guard: guard,
		logger: log.With("component", "ingest-v2"), now: time.Now}
}

// v2JobResult is stored on a completed v2 job.
type v2JobResult struct {
	ReportID string `json:"report_id"`
	Segment  *int   `json:"segment,omitempty"`
	Accepted int    `json:"accepted_findings"`
	Rejected int    `json:"rejected_findings"`
}

// Process runs one v2 job. A returned error is retried by the worker; on the
// last attempt the report is marked failed so the sensor sees it and may
// re-send.
func (p *V2JobProcessor) Process(ctx context.Context, job *ingestjob.Job) ([]byte, error) {
	seg := job.V2()
	if seg == nil {
		return nil, errors.New("v2 processor: job has no v2 binding")
	}
	rep, err := p.reports.GetByID(ctx, seg.ReportRef)
	if err != nil {
		return nil, fmt.Errorf("v2 processor: load report: %w", err)
	}
	result := v2JobResult{ReportID: rep.ReportID, Segment: seg.Seq}
	if rep.State == protov2.StateCompleted {
		// Finalized already (its payloads may be gone): a late retry of one
		// of its jobs has nothing left to do.
		return json.Marshal(result)
	}
	// The sensor may have been revoked, disabled or deleted while the
	// report waited in the queue (RFC-040 §5.2): its work is dropped, the
	// report fails so the sensor sees it, and nothing is retried.
	if p.sensors == nil {
		return nil, errors.New("v2 processor: sensor status check is not configured")
	}
	_, dropped, err := p.sensors.QueuedWorkSensor(ctx, rep.TenantID, &rep.SensorID, rep.ReportID)
	if err != nil {
		return nil, err
	}
	if dropped != nil {
		if err := p.reports.MarkFailed(ctx, rep.ID); err != nil {
			return nil, fmt.Errorf("v2 processor: fail report of a dropped sensor: %w", err)
		}
		// A chained step waiting for this report plans on what it has.
		p.service.commandIngestedNow(ctx, rep.TenantID, rep.CommandID)
		return json.Marshal(dropped)
	}

	if !seg.IsCommit() {
		r, err := p.processSegment(ctx, rep, job, *seg.Seq)
		if err != nil {
			p.failOnLastAttempt(ctx, job, rep)
			return nil, err
		}
		result.Accepted, result.Rejected = r.AcceptedFindings, r.RejectedFindings
	}
	if err := p.finalize(ctx, rep); err != nil {
		p.failOnLastAttempt(ctx, job, rep)
		return nil, err
	}
	return json.Marshal(result)
}

func (p *V2JobProcessor) failOnLastAttempt(ctx context.Context, job *ingestjob.Job, rep *ingestreport.Report) {
	if job.Attempts() < job.MaxAttempts() {
		return
	}
	if err := p.reports.MarkFailed(ctx, rep.ID); err != nil {
		p.logger.Error("v2: failed to mark report failed", "report_ref", rep.ID.String(), "error", err)
		return
	}
	metrics.IngestV2ReportsTotal.WithLabelValues(string(protov2.StateFailed), "none").Inc()
	// The report will never commit: a chained step waiting for it plans now
	// on what its predecessors produced (research/62 SG-10).
	p.service.commandIngestedNow(ctx, rep.TenantID, rep.CommandID)
}

func (p *V2JobProcessor) provenance(rep *ingestreport.Report, seq int, job *ingestjob.Job) Provenance {
	prov := Provenance{
		TenantID: rep.TenantID, SensorID: rep.SensorID, SensorType: rep.SensorType,
		CommandID: rep.CommandID, ScanZoneID: rep.ScanZoneID,
		ReportRef: rep.ID, ReportID: rep.ReportID, SegmentSeq: seq, MediaType: rep.MediaType,
	}
	if job != nil && job.V2() != nil {
		prov.ContentDigest = job.V2().ContentDigest
	}
	return prov
}

func (p *V2JobProcessor) processSegment(ctx context.Context, rep *ingestreport.Report, job *ingestjob.Job, seq int) (ingestreport.SegmentOutcome, error) {
	report, err := ParseV2Report(job.Payload(), rep.ReportID, p.limits)
	if err != nil {
		// The payload was validated before it was accepted; failing now
		// means it is unusable, and retrying will not change that. Record it
		// as a rejected segment instead of failing the report.
		p.logger.Error("v2: stored segment no longer parses", "report_ref", rep.ID.String(), "segment", seq)
		o := ingestreport.SegmentOutcome{Errors: []protov2.ItemError{{
			Pointer: "", Code: protov2.CodeProcessingFailed, Detail: protov2.DetailProcessingFailed}}}
		return o, p.reports.RecordSegmentOutcome(ctx, rep.ID, seq, o, nil)
	}
	if rep.CommandID == nil {
		// A report without a command (RFC-040 §5.3): quarantined or applied
		// with the unsolicited limits, decided here once per segment.
		if o, held, err := p.service.admitV2Segment(ctx, p.provenance(rep, seq, job), report); err != nil {
			return ingestreport.SegmentOutcome{}, err
		} else if held {
			if err := p.reports.RecordSegmentOutcome(ctx, rep.ID, seq, o, nil); err != nil {
				return ingestreport.SegmentOutcome{}, err
			}
			observeItems(o)
			return o, nil
		}
	}
	res, err := p.service.IngestV2Segment(ctx, p.provenance(rep, seq, job), report)
	if err != nil {
		return ingestreport.SegmentOutcome{}, fmt.Errorf("v2: ingest segment: %w", err)
	}
	if err := p.reports.RecordSegmentOutcome(ctx, rep.ID, seq, res.Outcome, res.Touched); err != nil {
		return ingestreport.SegmentOutcome{}, err
	}
	observeItems(res.Outcome)
	return res.Outcome, nil
}

// finalize claims and runs the commit-time steps when the report is committed
// and every segment has an outcome. Losing the claim is not an error: another
// job, or a later one, finalizes.
func (p *V2JobProcessor) finalize(ctx context.Context, rep *ingestreport.Report) error {
	claimed, ok, err := p.reports.ClaimFinalize(ctx, rep.ID)
	if err != nil {
		return fmt.Errorf("v2: claim finalize: %w", err)
	}
	if !ok {
		return nil
	}
	var header V2Header
	if err := json.Unmarshal(claimed.Header, &header); err != nil {
		p.logger.Error("v2: stored header does not parse", "report_ref", claimed.ID.String())
	}
	res := p.service.CommitV2Report(ctx, p.provenance(claimed, -1, nil), header, claimed.TouchedAssetIDs, p.guard)
	if err := p.reports.Finish(ctx, claimed.ID, protov2.StateCompleted, res.AutoResolved, res.AutoResolve); err != nil {
		return fmt.Errorf("v2: finish report: %w", err)
	}
	metrics.IngestV2ReportsTotal.WithLabelValues(string(protov2.StateCompleted), res.AutoResolve).Inc()
	p.service.recordV2ReportStats(ctx, claimed)
	// The command may already be completed: then this report was the last
	// half of its coverage evidence.
	if claimed.CommandID != nil {
		p.service.EvaluateCommandCoverage(ctx, claimed.TenantID, *claimed.CommandID)
		// A chained step waiting for this report's ingest is planned now.
		p.service.commandIngestedNow(ctx, claimed.TenantID, claimed.CommandID)
	}
	if err := p.jobs.ClearV2Payloads(ctx, claimed.ID); err != nil {
		p.logger.Warn("v2: could not clear segment payloads", "report_ref", claimed.ID.String(), "error", err)
	}
	p.logger.Info("v2 report completed", "report_ref", claimed.ID.String(), "report_id", claimed.ReportID,
		"segments", claimed.SegmentsReceived, "auto_resolve", res.AutoResolve, "auto_resolved", res.AutoResolved)
	return nil
}

// Housekeep expires uncommitted reports past their window and, every
// stagingPurgeEvery, purges the staging data of reports that will never be
// applied (PurgeStaging). The worker calls it on every drain cycle.
func (p *V2JobProcessor) Housekeep(ctx context.Context) {
	n, err := p.reports.ExpireStale(ctx, p.now())
	if err != nil {
		p.logger.Warn("v2: expiry sweep failed", "error", err)
		return
	}
	if n > 0 {
		metrics.IngestV2ReportsTotal.WithLabelValues(string(protov2.StateExpired), "none").Add(float64(n))
		p.logger.Info("v2: expired uncommitted reports", "count", n)
	}
	p.purgeStaging(ctx)
}

// purgeStaging bounds the staging tables: without it, every segment of a
// report that is abandoned, expires or fails kept its decoded payload (up
// to 64 MiB) forever, and a sensor could fill the database disk by opening,
// filling and abandoning reports.
func (p *V2JobProcessor) purgeStaging(ctx context.Context) {
	purger, ok := p.reports.(stagingPurger)
	now := p.now()
	if !ok || (!p.lastPurge.IsZero() && now.Sub(p.lastPurge) < stagingPurgeEvery) {
		return
	}
	p.lastPurge = now
	out, err := purger.PurgeStaging(ctx, now.Add(-StagingRetention), stagingPurgeBatch)
	if err != nil {
		p.logger.Warn("v2: staging purge failed", "error", err)
		return
	}
	if out != (ingestreport.StagingPurge{}) {
		p.logger.Info("v2: purged staging data", "payloads_cleared", out.PayloadsCleared,
			"reports_deleted", out.ReportsDeleted, "jobs_deleted", out.JobsDeleted)
	}
}

// observeItems counts a segment's items in ingest_v2_items_total.
func observeItems(o ingestreport.SegmentOutcome) {
	for _, c := range []struct {
		kind, result string
		n            int
	}{
		{"asset", "accepted", o.AcceptedAssets}, {"asset", "rejected", o.RejectedAssets},
		{"asset", "quarantined", o.QuarantinedAssets},
		{"finding", "accepted", o.AcceptedFindings}, {"finding", "rejected", o.RejectedFindings},
		{"finding", "quarantined", o.QuarantinedFindings},
	} {
		if c.n > 0 {
			metrics.IngestV2ItemsTotal.WithLabelValues(c.kind, c.result).Add(float64(c.n))
		}
	}
}

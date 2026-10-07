package ingest

// Accept side of sensor protocol v2 results (RFC-026 §3,
// docs/rfcs/RFC-026-sensor-results-ingest.md): the checks that need the
// database, then store and enqueue. The edge middleware has already
// authenticated the sensor, checked the headers, verified the digest and
// decoded the content with a bound; this file decides what the verified
// bytes may become.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// v2CommandReader is the slice of the command repository the receiver needs.
type v2CommandReader interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*command.Command, error)
}

// v2QueueDepth is the slice of the v1 ingest queue the receiver needs for
// per-tenant backpressure.
type v2QueueDepth interface {
	CountPendingByTenant(ctx context.Context, tenantID shared.ID) (int, error)
}

// V2Receiver accepts v2 segments and commits.
type V2Receiver struct {
	reports    ingestreport.Repository
	jobs       ingestjob.V2Repository
	queue      v2QueueDepth
	commands   v2CommandReader
	limits     protov2.Limits
	maxPending int
	logger     *logger.Logger
	now        func() time.Time
}

// NewV2Receiver wires the receiver. maxPendingPerTenant bounds a tenant's
// queue (0 disables the check), as INGEST_MAX_PENDING_PER_TENANT does for v1.
func NewV2Receiver(reports ingestreport.Repository, jobs ingestjob.V2Repository, queue v2QueueDepth,
	commands v2CommandReader, limits protov2.Limits, maxPendingPerTenant int, log *logger.Logger,
) *V2Receiver {
	if log == nil {
		log = logger.NewNop()
	}
	return &V2Receiver{reports: reports, jobs: jobs, queue: queue, commands: commands, limits: limits,
		maxPending: maxPendingPerTenant, logger: log.With("component", "ingest-v2"), now: time.Now}
}

// Limits are the limits the receiver enforces (published on hello).
func (v *V2Receiver) Limits() protov2.Limits { return v.limits }

// V2Body is the verified content of a request.
type V2Body struct {
	Decoded []byte
	Digest  string
}

// V2Target names the report a request addresses: the sensor that sent it,
// the optional command it is bound to, and the report id.
type V2Target struct {
	Sensor    *sensor.Sensor
	CommandID string // "" for the unsolicited form
	ReportID  string
	UserAgent string
}

// Problem returns a *V2ReportError for a problem type.
func problem(t protov2.ProblemType) *V2ReportError { return &V2ReportError{Problem: t} }

// PutResult is the outcome of a PUT.
type PutResult struct {
	Status protov2.Status
	// Created is false for an identical replay (200); true when the segment
	// was stored now, or a failed report was re-queued (202).
	Created bool
}

// openCommand returns the command a bound request names, when it is assigned
// to this sensor and still open (RFC-023 C-8): claimed and not finished, or
// finished less than CommandGraceAfterFinish ago. Anything else is
// command-not-found, so a sensor learns nothing about other commands.
func (v *V2Receiver) openCommand(ctx context.Context, tenantID shared.ID, t V2Target) (*command.Command, error) {
	if t.CommandID == "" {
		return nil, nil
	}
	if t.Sensor == nil || t.Sensor.TenantID == nil || *t.Sensor.TenantID != tenantID {
		return nil, problem(protov2.ProblemCommandNotFound)
	}
	cmd, err := OpenCommand(ctx, v.commands, t.Sensor, t.CommandID, v.now())
	if err != nil {
		return nil, problem(protov2.ProblemCommandNotFound)
	}
	return cmd, nil
}

// commandTool is the tool a command asks for (payload "scanner", else
// "preferred_tool"; the same keys the zone claim predicate reads), or "".
func commandTool(cmd *command.Command) string {
	if cmd == nil || len(cmd.Payload) == 0 {
		return ""
	}
	var p struct {
		Scanner       string `json:"scanner"`
		PreferredTool string `json:"preferred_tool"`
	}
	if json.Unmarshal(cmd.Payload, &p) != nil {
		return ""
	}
	if p.Scanner != "" {
		return p.Scanner
	}
	return p.PreferredTool
}

func sameCommand(rep *ingestreport.Report, cmd *command.Command) bool {
	switch {
	case rep.CommandID == nil && cmd == nil:
		return true
	case rep.CommandID != nil && cmd != nil:
		return *rep.CommandID == cmd.ID
	default:
		return false
	}
}

// tenantOf is the tenant a sensor reports for: always its own. A sensor with
// no tenant (platform sensors, which this schema cannot hold) is refused.
func tenantOf(s *sensor.Sensor) (shared.ID, error) {
	if s == nil || s.TenantID == nil || s.TenantID.IsZero() {
		return shared.ID{}, problem(protov2.ProblemScopeDenied)
	}
	return *s.TenantID, nil
}

// Put stores one segment. seq is the segment number; whole is true for the
// single-request form (PUT /results/{id}), which is segment 0 plus an
// implicit commit.
//
//nolint:cyclop,gocognit,funlen // the RFC-026 §3.3 decision sequence, one check per step
func (v *V2Receiver) Put(ctx context.Context, t V2Target, seq int, whole bool, body V2Body) (*PutResult, error) {
	tenantID, err := tenantOf(t.Sensor)
	if err != nil {
		return nil, err
	}
	cmd, err := v.openCommand(ctx, tenantID, t)
	if err != nil {
		return nil, err
	}
	now := v.now()

	rep, err := v.reports.Get(ctx, tenantID, t.Sensor.ID, t.ReportID)
	switch {
	case errors.Is(err, ingestreport.ErrNotFound):
		rep = nil
	case err != nil:
		return nil, err
	}

	if rep != nil {
		if !sameCommand(rep, cmd) {
			return nil, problem(protov2.ProblemBindingMismatch)
		}
		// Replay or conflict on a segment the server already holds.
		existing, err := v.jobs.GetV2Segment(ctx, rep.ID, seq)
		switch {
		case err == nil:
			return v.replay(ctx, rep, existing, body, now)
		case !errors.Is(err, shared.ErrNotFound):
			return nil, err
		}
		if whole || rep.ImplicitCommit {
			// A whole report is exactly one segment; a second, different
			// one under the same id is a conflict, not a new segment.
			return nil, problem(protov2.ProblemReportConflict)
		}
		if rep.Committed() {
			return nil, problem(protov2.ProblemReportCommitted)
		}
		if rep.Expired(now) {
			return nil, problem(protov2.ProblemReportExpired)
		}
	}

	report, err := ParseV2Report(body.Decoded, t.ReportID, v.limits)
	if err != nil {
		return nil, err
	}
	// Canonical before the checks and the header digest, so every segment
	// of a report, and ingest_reports.tool_name, carry one name.
	report.Tool.Name = tooldom.CanonicalName(report.Tool.Name)
	// The sensor's effective tools: what it reports installed (none before
	// its first report).
	if !SensorDeclaresTool(t.Sensor.EffectiveTools(), report.Tool.Name) {
		return nil, problem(protov2.ProblemToolNotPermitted)
	}
	if ct := commandTool(cmd); ct != "" && !tooldom.SameTool(ct, report.Tool.Name) {
		return nil, problem(protov2.ProblemToolNotPermitted)
	}
	header, headerDigest, err := V2HeaderOf(report)
	if err != nil {
		return nil, err
	}
	if rep != nil && rep.HeaderDigest != headerDigest {
		return nil, problem(protov2.ProblemSegmentHeaderMismatch)
	}

	if v.maxPending > 0 {
		if n, err := v.queue.CountPendingByTenant(ctx, tenantID); err == nil && n >= v.maxPending {
			return nil, problem(protov2.ProblemQueueFull)
		}
	}

	if rep == nil {
		if rep, err = v.createReport(ctx, t, tenantID, cmd, whole, header, headerDigest, report.Tool.Name, now); err != nil {
			return nil, err
		}
	}

	ok, err := v.reports.ReserveSegment(ctx, rep.ID, len(report.Assets), len(report.Findings),
		v.limits.MaxAssetsPerReport, v.limits.MaxFindingsPerReport, now.Add(v.uncommittedTTL()))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &V2ReportError{Problem: protov2.ProblemReportTooLarge}
	}

	s := seq
	job := ingestjob.NewV2Job(tenantID, &t.Sensor.ID, t.ReportID, ingestjob.V2Segment{
		ReportRef: rep.ID, Seq: &s, ContentDigest: body.Digest, MediaType: protov2.MediaTypeCTIS,
	}, body.Decoded)
	stored, created, err := v.jobs.EnqueueV2(ctx, job)
	if err != nil {
		_ = v.reports.ReleaseSegment(ctx, rep.ID, len(report.Assets), len(report.Findings))
		return nil, err
	}
	if !created {
		// A concurrent request stored this segment first.
		_ = v.reports.ReleaseSegment(ctx, rep.ID, len(report.Assets), len(report.Findings))
		return v.replay(ctx, rep, stored, body, now)
	}

	if whole {
		if err := v.commit(ctx, rep, 1, true, now); err != nil {
			return nil, err
		}
	}
	st, err := v.status(ctx, rep.ID, now)
	if err != nil {
		return nil, err
	}
	return &PutResult{Status: st, Created: true}, nil
}

// createReport creates the report a first segment names. A concurrent
// request that created it first wins; this request then continues on that
// row when its header and binding agree.
func (v *V2Receiver) createReport(ctx context.Context, t V2Target, tenantID shared.ID, cmd *command.Command,
	whole bool, header []byte, headerDigest, toolName string, now time.Time,
) (*ingestreport.Report, error) {
	if !whole {
		n, err := v.reports.CountOpen(ctx, t.Sensor.ID, now)
		if err != nil {
			return nil, err
		}
		if n >= v.limits.MaxOpenReportsPerSensor {
			return nil, problem(protov2.ProblemTooManyOpenReport)
		}
	}
	rep := &ingestreport.Report{
		ID: shared.NewID(), TenantID: tenantID, SensorID: t.Sensor.ID, ReportID: t.ReportID,
		State: protov2.StateReceiving, MediaType: protov2.MediaTypeCTIS, SensorType: string(t.Sensor.Type),
		UserAgent: truncateString(sanitizeIngestLogField(t.UserAgent), 256), HeaderDigest: headerDigest, Header: header,
		ToolName: toolName, ImplicitCommit: whole,
		ExpiresAt: now.Add(v.uncommittedTTL()), ReceivedAt: now,
	}
	if cmd != nil {
		rep.CommandID = &cmd.ID
		rep.ScanZoneID = cmd.ScanZoneID
	}
	err := v.reports.Create(ctx, rep)
	if err == nil {
		return rep, nil
	}
	if !errors.Is(err, ingestreport.ErrExists) {
		return nil, err
	}
	existing, err := v.reports.Get(ctx, tenantID, t.Sensor.ID, t.ReportID)
	if err != nil {
		return nil, err
	}
	if existing.HeaderDigest != headerDigest {
		return nil, problem(protov2.ProblemSegmentHeaderMismatch)
	}
	if !sameCommand(existing, cmd) {
		return nil, problem(protov2.ProblemBindingMismatch)
	}
	return existing, nil
}

// replay answers a PUT for a segment the server already holds: the same
// digest is an idempotent replay (and re-queues a failed report), a
// different digest is a conflict.
func (v *V2Receiver) replay(ctx context.Context, rep *ingestreport.Report, existing *ingestjob.Job, body V2Body, now time.Time) (*PutResult, error) {
	if existing.V2() == nil || existing.V2().ContentDigest != body.Digest {
		return nil, problem(protov2.ProblemReportConflict)
	}
	created := false
	if rep.State == protov2.StateFailed {
		if _, err := v.jobs.RequeueDeadV2(ctx, rep.ID); err != nil {
			return nil, err
		}
		if err := v.reports.Reopen(ctx, rep.ID, now.Add(v.uncommittedTTL())); err != nil {
			return nil, err
		}
		created = true
	}
	st, err := v.status(ctx, rep.ID, now)
	if err != nil {
		return nil, err
	}
	return &PutResult{Status: st, Created: created}, nil
}

// Commit closes a segmented report (POST .../commit). An identical repeated
// commit is a replay (created=false).
func (v *V2Receiver) Commit(ctx context.Context, t V2Target, req protov2.CommitRequest) (*PutResult, error) {
	tenantID, err := tenantOf(t.Sensor)
	if err != nil {
		return nil, err
	}
	cmd, err := v.openCommand(ctx, tenantID, t)
	if err != nil {
		return nil, err
	}
	if req.SegmentCount < 1 || req.SegmentCount > v.limits.MaxSegmentsPerReport || len(req.SegmentDigests) != req.SegmentCount {
		return nil, problem(protov2.ProblemInvalidRequest)
	}
	want := make([]string, len(req.SegmentDigests))
	for i, d := range req.SegmentDigests {
		c, ok := protov2.CanonicalSHA256(d)
		if !ok {
			return nil, problem(protov2.ProblemInvalidRequest)
		}
		want[i] = c
	}

	now := v.now()
	rep, err := v.reports.Get(ctx, tenantID, t.Sensor.ID, t.ReportID)
	if errors.Is(err, ingestreport.ErrNotFound) {
		return nil, problem(protov2.ProblemReportNotFound)
	}
	if err != nil {
		return nil, err
	}
	if !sameCommand(rep, cmd) {
		return nil, problem(protov2.ProblemBindingMismatch)
	}

	stored, err := v.jobs.V2SegmentDigests(ctx, rep.ID)
	if err != nil {
		return nil, err
	}
	matches := len(stored) == req.SegmentCount
	for i := 0; matches && i < req.SegmentCount; i++ {
		if stored[i] != want[i] {
			matches = false
		}
	}

	if rep.Committed() {
		if rep.ImplicitCommit || !matches || rep.SegmentCount == nil || *rep.SegmentCount != req.SegmentCount {
			return nil, problem(protov2.ProblemReportCommitted)
		}
		st, err := v.status(ctx, rep.ID, now)
		if err != nil {
			return nil, err
		}
		return &PutResult{Status: st, Created: false}, nil
	}
	if rep.Expired(now) {
		return nil, problem(protov2.ProblemReportExpired)
	}
	if !matches {
		return nil, problem(protov2.ProblemSegmentSetMismatch)
	}
	if err := v.commit(ctx, rep, req.SegmentCount, false, now); err != nil {
		return nil, err
	}
	st, err := v.status(ctx, rep.ID, now)
	if err != nil {
		return nil, err
	}
	return &PutResult{Status: st, Created: true}, nil
}

func (v *V2Receiver) commit(ctx context.Context, rep *ingestreport.Report, count int, implicit bool, now time.Time) error {
	ok, err := v.reports.Commit(ctx, rep.ID, count, implicit, now)
	if err != nil {
		return err
	}
	if !ok {
		return problem(protov2.ProblemReportCommitted)
	}
	job := ingestjob.NewV2Job(rep.TenantID, &rep.SensorID, rep.ReportID, ingestjob.V2Segment{ReportRef: rep.ID}, nil)
	if _, _, err := v.jobs.EnqueueV2(ctx, job); err != nil {
		return fmt.Errorf("enqueue v2 commit: %w", err)
	}
	return nil
}

// Status returns the status resource of a report the sensor owns.
func (v *V2Receiver) Status(ctx context.Context, t V2Target) (protov2.Status, error) {
	tenantID, err := tenantOf(t.Sensor)
	if err != nil {
		return protov2.Status{}, err
	}
	rep, err := v.reports.Get(ctx, tenantID, t.Sensor.ID, t.ReportID)
	if errors.Is(err, ingestreport.ErrNotFound) {
		return protov2.Status{}, problem(protov2.ProblemReportNotFound)
	}
	if err != nil {
		return protov2.Status{}, err
	}
	return rep.Status(v.now()), nil
}

// Abandon gives up an uncommitted segmented report (DELETE). Its upserts
// stay; it never auto-resolves.
func (v *V2Receiver) Abandon(ctx context.Context, t V2Target) error {
	tenantID, err := tenantOf(t.Sensor)
	if err != nil {
		return err
	}
	rep, err := v.reports.Get(ctx, tenantID, t.Sensor.ID, t.ReportID)
	if errors.Is(err, ingestreport.ErrNotFound) {
		return problem(protov2.ProblemReportNotFound)
	}
	if err != nil {
		return err
	}
	if rep.Committed() {
		return problem(protov2.ProblemReportCommitted)
	}
	if rep.Expired(v.now()) {
		return nil // already gone the same way
	}
	if _, err := v.reports.Abandon(ctx, rep.ID); err != nil {
		return err
	}
	return nil
}

func (v *V2Receiver) status(ctx context.Context, id shared.ID, now time.Time) (protov2.Status, error) {
	rep, err := v.reports.GetByID(ctx, id)
	if err != nil {
		return protov2.Status{}, err
	}
	return rep.Status(now), nil
}

func (v *V2Receiver) uncommittedTTL() time.Duration {
	if v.limits.UncommittedTTLSeconds > 0 {
		return time.Duration(v.limits.UncommittedTTLSeconds) * time.Second
	}
	return protov2.DefaultUncommittedTTL
}

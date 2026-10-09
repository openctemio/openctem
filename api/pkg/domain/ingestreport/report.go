// Package ingestreport is the domain of sensor protocol v2 results reports
// (RFC-026, docs/rfcs/RFC-026-sensor-results-ingest.md): a report a sensor
// names with its own UUID, sent as one or more self-describing segments and
// closed by a commit. Segments travel through the RFC-005 ingest_jobs queue;
// this package tracks the report they belong to.
package ingestreport

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// State is the report lifecycle state. The values are the wire values of the
// status resource.
type State = protov2.ReportState

// Errors.
var (
	ErrNotFound = shared.NewDomainError("NOT_FOUND", "ingest report not found", shared.ErrNotFound)
	// ErrExists: a report with this (tenant, sensor, report_id) exists.
	ErrExists = shared.NewDomainError("CONFLICT", "ingest report exists", shared.ErrConflict)
)

// SegmentOutcome is what processing one segment produced. It is stored per
// segment number, so a segment the worker retries overwrites its own entry
// instead of adding to the totals.
type SegmentOutcome struct {
	AcceptedAssets      int                 `json:"accepted_assets"`
	AcceptedFindings    int                 `json:"accepted_findings"`
	RejectedAssets      int                 `json:"rejected_assets"`
	RejectedFindings    int                 `json:"rejected_findings"`
	QuarantinedAssets   int                 `json:"quarantined_assets"`
	QuarantinedFindings int                 `json:"quarantined_findings"`
	Errors              []protov2.ItemError `json:"errors,omitempty"`
	ErrorsTruncated     bool                `json:"errors_truncated,omitempty"`
}

// Report is one v2 results report.
type Report struct {
	ID         shared.ID
	TenantID   shared.ID
	SensorID   shared.ID
	ReportID   string
	CommandID  *shared.ID
	ScanZoneID *shared.ID
	State      State

	// Provenance stamped by the server.
	MediaType  string
	SensorType string
	UserAgent  string

	// HeaderDigest fingerprints the tool + metadata every segment repeats;
	// Header is that canonical JSON, read by the commit-time steps.
	HeaderDigest string
	Header       []byte
	ToolName     string

	ImplicitCommit   bool
	SegmentCount     *int
	SegmentsReceived int
	AssetsReceived   int
	FindingsReceived int
	CommittedAt      *time.Time

	Outcomes        map[int]SegmentOutcome
	TouchedAssetIDs []shared.ID
	AutoResolved    int
	AutoResolve     string

	ExpiresAt  time.Time
	ReceivedAt time.Time
	UpdatedAt  time.Time
}

// Committed reports whether the commit (explicit or implicit) was received.
func (r *Report) Committed() bool { return r.CommittedAt != nil }

// Expired reports whether an uncommitted report is past its expiry at now.
// The stored state may lag until the sweep runs; readers use this.
func (r *Report) Expired(now time.Time) bool {
	return r.State == protov2.StateExpired ||
		(r.State == protov2.StateReceiving && !r.Committed() && now.After(r.ExpiresAt))
}

// Status renders the report as the v2 status resource.
func (r *Report) Status(now time.Time) protov2.Status {
	st := protov2.Status{
		ReportID:     r.ReportID,
		State:        r.State,
		Segments:     protov2.SegmentCounts{Received: r.SegmentsReceived, Expected: r.SegmentCount},
		AutoResolved: r.AutoResolved,
		AutoResolve:  r.AutoResolve,
		Errors:       []protov2.ItemError{},
		ReceivedAt:   r.ReceivedAt.UTC(),
		UpdatedAt:    r.UpdatedAt.UTC(),
	}
	if r.CommandID != nil {
		st.CommandID = r.CommandID.String()
	}
	if r.Expired(now) {
		st.State = protov2.StateExpired
	}
	// A committed report whose segments are still waiting reads "queued";
	// before the commit it reads "receiving" whatever the worker has done.
	seqs := make([]int, 0, len(r.Outcomes))
	for seq := range r.Outcomes {
		seqs = append(seqs, seq)
	}
	sort.Ints(seqs)
	for _, seq := range seqs {
		o := r.Outcomes[seq]
		st.Accepted.Assets += o.AcceptedAssets
		st.Accepted.Findings += o.AcceptedFindings
		st.Rejected.Assets += o.RejectedAssets
		st.Rejected.Findings += o.RejectedFindings
		st.Quarantined.Assets += o.QuarantinedAssets
		st.Quarantined.Findings += o.QuarantinedFindings
		if o.ErrorsTruncated {
			st.ErrorsTruncated = true
		}
		for _, e := range o.Errors {
			if len(st.Errors) >= protov2.MaxItemErrors {
				st.ErrorsTruncated = true
				break
			}
			s := seq
			e.Segment = &s
			st.Errors = append(st.Errors, e)
		}
	}
	return st
}

// Processed is how many distinct segments the worker finished.
func (r *Report) Processed() int { return len(r.Outcomes) }

// OutcomeKey is the JSON key a segment's outcome is stored under.
func OutcomeKey(seq int) string { return strconv.Itoa(seq) }

// ParseOutcomes decodes the stored outcome map's keys.
func ParseOutcomes(raw map[string]SegmentOutcome) (map[int]SegmentOutcome, error) {
	out := make(map[int]SegmentOutcome, len(raw))
	for k, v := range raw {
		n, err := strconv.Atoi(k)
		if err != nil {
			return nil, errors.New("ingest report: malformed segment outcome key")
		}
		out[n] = v
	}
	return out, nil
}

// Repository persists v2 reports. Every method that takes a tenant is scoped
// to it; the worker-side methods take the report's primary key, which only
// the server ever learns.
type Repository interface {
	// Create inserts r. A report with the same (tenant, sensor, report_id)
	// already existing is ErrExists.
	Create(ctx context.Context, r *Report) error

	// Get returns the report a sensor named, scoped to its tenant and sensor.
	Get(ctx context.Context, tenantID, sensorID shared.ID, reportID string) (*Report, error)

	// GetByID returns a report by primary key (worker side).
	GetByID(ctx context.Context, id shared.ID) (*Report, error)

	// CountOpen counts a sensor's uncommitted, unexpired reports.
	CountOpen(ctx context.Context, sensorID shared.ID, now time.Time) (int, error)

	// ReserveSegment counts a segment about to be queued, with its item
	// counts, and pushes the expiry out to expiresAt. It refuses (false) when
	// the report's totals would pass maxAssets or maxFindings; the check and
	// the increment are one statement, so parallel segments cannot overshoot.
	ReserveSegment(ctx context.Context, id shared.ID, assets, findings, maxAssets, maxFindings int, expiresAt time.Time) (bool, error)

	// ReleaseSegment undoes ReserveSegment for a segment that was not queued
	// after all (a concurrent request stored the same segment first).
	ReleaseSegment(ctx context.Context, id shared.ID, assets, findings int) error

	// Abandon marks an uncommitted report expired at the sensor's request.
	// False when it is committed or no longer receiving.
	Abandon(ctx context.Context, id shared.ID) (bool, error)

	// Commit closes the report with segmentCount segments. False when it was
	// already committed or is no longer receiving.
	Commit(ctx context.Context, id shared.ID, segmentCount int, implicit bool, at time.Time) (bool, error)

	// RecordSegmentOutcome stores (or replaces) a segment's outcome and adds
	// the asset ids it touched.
	RecordSegmentOutcome(ctx context.Context, id shared.ID, seq int, o SegmentOutcome, touched []shared.ID) error

	// ClaimFinalize moves a committed report whose every segment has an
	// outcome to processing, exactly once. The report is returned when this
	// caller won the claim.
	ClaimFinalize(ctx context.Context, id shared.ID) (*Report, bool, error)

	// Finish records the final state and the auto-resolve outcome.
	Finish(ctx context.Context, id shared.ID, state State, autoResolved int, autoResolve string) error

	// MarkFailed marks a report failed after a segment or its commit
	// exhausted the worker's retries.
	MarkFailed(ctx context.Context, id shared.ID) error

	// Reopen returns a failed report to the state it was in before (queued
	// when committed, receiving otherwise), for a sensor that re-sends it.
	Reopen(ctx context.Context, id shared.ID, expiresAt time.Time) error

	// ExpireStale marks uncommitted reports past their expiry expired.
	ExpireStale(ctx context.Context, now time.Time) (int, error)
}

// StagingPurge is what one staging purge removed.
type StagingPurge struct {
	// PayloadsCleared are segment payloads of expired reports emptied.
	PayloadsCleared int
	// ReportsDeleted are failed and expired reports deleted (with their
	// jobs).
	ReportsDeleted int
	// JobsDeleted are finished jobs without a report deleted.
	JobsDeleted int
}

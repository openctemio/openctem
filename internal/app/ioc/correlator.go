// Package ioc wires Indicators of Compromise to the runtime
// telemetry stream. When an agent reports an event whose properties
// match a known IOC, the source finding is auto-reopened — the loop
// edge named "invariant B6" in the CTEM model.
//
// The correlator is deliberately passive: it never deletes telemetry,
// never alters the event, and records every match in ioc_matches so
// an operator can answer "why was this finding reopened?" after the
// fact.
package ioc

import (
	"context"
	"fmt"
	"time"

	iocdom "github.com/openctemio/api/pkg/domain/ioc"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/telemetry"
	"github.com/openctemio/api/pkg/logger"
)

// FindingReopener is the narrow surface the correlator needs to
// reopen a closed finding when an IOC fires. The implementation is
// expected to:
//
//   - no-op when the finding is already open (not closed)
//   - transition closed → in_progress atomically
//   - emit an audit event describing the reopen
//   - return (true, nil) when a real reopen happened; (false, nil)
//     when the finding was already open
//
// Kept here as an interface so the correlator does not drag the full
// FindingActionsService into its import graph; the wire-up passes a
// thin adapter.
type FindingReopener interface {
	ReopenForIOCMatch(ctx context.Context, tenantID, findingID shared.ID, reason string) (reopened bool, err error)
}

// Correlator consumes (tenantID, telemetry event) pairs and fires
// match + reopen side effects.
type Correlator struct {
	iocs     iocdom.Repository
	reopener FindingReopener
	logger   *logger.Logger
	// now lets tests inject a deterministic clock.
	now func() time.Time
}

// NewCorrelator wires deps.
func NewCorrelator(iocs iocdom.Repository, reopener FindingReopener, log *logger.Logger) *Correlator {
	if log == nil {
		log = logger.NewNop()
	}
	return &Correlator{
		iocs:     iocs,
		reopener: reopener,
		logger:   log.With("component", "ioc-correlator"),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// TelemetryEvent is the minimal shape the correlator needs from a
// runtime_telemetry_events row. The handler already has the full
// row; it projects down to this struct before calling Correlate so
// the correlator does not depend on the telemetry storage layout.
type TelemetryEvent struct {
	ID         shared.ID
	EventType  string
	Properties map[string]any
}

// Correlate scans one telemetry event against the tenant's active
// IOC catalogue, records a match for each hit, and reopens any
// closed source finding the IOC points at.
//
// Returns the matched indicators so callers that want to surface
// the hit count on a dashboard can do so. Errors are logged and
// continued-through per-IOC — one bad finding update must not block
// the other matches in the same event.
func (c *Correlator) Correlate(
	ctx context.Context,
	tenantID shared.ID,
	event TelemetryEvent,
) ([]*iocdom.Indicator, error) {
	candidates := ExtractCandidates(event)
	if len(candidates) == 0 {
		return nil, nil
	}

	hits, err := c.iocs.FindActiveByValues(ctx, tenantID, candidates)
	if err != nil {
		return nil, fmt.Errorf("ioc lookup: %w", err)
	}
	if len(hits) == 0 {
		return nil, nil
	}

	for _, ind := range hits {
		c.handleHit(ctx, tenantID, event, ind)
	}
	return hits, nil
}

// handleHit records the match row and drives the reopen path when
// the IOC links back to a finding. Per-match failures are logged but
// not propagated — the rest of the batch must keep processing.
func (c *Correlator) handleHit(
	ctx context.Context,
	tenantID shared.ID,
	event TelemetryEvent,
	ind *iocdom.Indicator,
) {
	match := iocdom.Match{
		ID:        shared.NewID(),
		TenantID:  tenantID,
		IOCID:     ind.ID,
		MatchedAt: c.now(),
	}
	if !event.ID.IsZero() {
		eid := event.ID
		match.TelemetryEventID = &eid
	}
	if ind.SourceFindingID != nil && c.reopener != nil {
		fid := *ind.SourceFindingID
		match.FindingID = &fid

		reason := fmt.Sprintf("ioc auto-reopen: runtime match on %s=%s", ind.Type, ind.Value)
		reopened, err := c.reopener.ReopenForIOCMatch(ctx, tenantID, fid, reason)
		if err != nil {
			c.logger.Warn("auto-reopen failed",
				"tenant_id", tenantID.String(),
				"ioc_id", ind.ID.String(),
				"finding_id", fid.String(),
				"error", err,
			)
		}
		match.Reopened = reopened
	}
	if err := c.iocs.RecordMatch(ctx, match); err != nil {
		c.logger.Warn("ioc match record failed",
			"tenant_id", tenantID.String(),
			"ioc_id", ind.ID.String(),
			"error", err,
		)
	}
}

// ExtractCandidates pulls every IOC-matchable token out of an
// event's properties. Kept as a package-level function so the
// postgres ingest path + tests can reuse the exact same extraction
// logic without instantiating a Correlator.
//
// Property keys come from pkg/domain/telemetry — the agent wire
// contract. Unknown properties are ignored (whitelist) so a garbage
// field in properties can't generate false candidate IOCs.
func ExtractCandidates(event TelemetryEvent) []iocdom.Candidate {
	if len(event.Properties) == 0 {
		return nil
	}
	var out []iocdom.Candidate
	add := func(t iocdom.Type, key string) {
		raw, ok := event.Properties[key]
		if !ok {
			return
		}
		s, ok := raw.(string)
		if !ok || s == "" {
			return
		}
		norm := iocdom.Normalise(t, s)
		if norm == "" {
			return
		}
		out = append(out, iocdom.Candidate{Type: t, Normalised: norm})
	}

	// IPs
	add(iocdom.TypeIP, telemetry.PropRemoteIP)
	add(iocdom.TypeIP, telemetry.PropSourceIP)

	// Domains
	add(iocdom.TypeDomain, telemetry.PropRemoteDomain)
	add(iocdom.TypeDomain, telemetry.PropQueryName)

	// URLs
	add(iocdom.TypeURL, telemetry.PropRemoteURL)
	add(iocdom.TypeURL, telemetry.PropURL)

	// File hashes
	add(iocdom.TypeFileHash, telemetry.PropImageHash)
	add(iocdom.TypeFileHash, telemetry.PropFileHash)

	// Process names
	add(iocdom.TypeProcessName, telemetry.PropProcessName)

	// User agents
	add(iocdom.TypeUserAgent, telemetry.PropUserAgent)

	return out
}

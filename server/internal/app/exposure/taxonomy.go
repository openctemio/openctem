package exposure

// Exposure taxonomy commands (docs/architecture/exposure-taxonomy.md): the
// in-progress state, the analyst severity override and the display-category
// filter and counts.

import (
	"context"
	"fmt"
	"slices"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SeverityStore persists an exposure's effective severity and its override
// provenance (*postgres.ExposureRepository).
type SeverityStore interface {
	SaveSeverity(ctx context.Context, event *exposuredom.ExposureEvent) error
}

// SetSeverityStore wires the severity store. Unwired, ChangeSeverity
// refuses (fail closed).
func (s *ExposureService) SetSeverityStore(st SeverityStore) { s.severities = st }

// SetAuditService wires the audit log for exposure commands that record
// their own entry (the severity override).
func (s *ExposureService) SetAuditService(a *auditapp.AuditService) { s.audit = a }

// StartProgress marks an open exposure as being worked on, as the caller.
// The lookup is tenant-scoped and data-scope checked: an exposure of another
// tenant, or on an asset outside the caller's scope, is not found.
func (s *ExposureService) StartProgress(ctx context.Context, tenantID, exposureID, userID, notes string) (*exposuredom.ExposureEvent, error) {
	return s.changeState(ctx, tenantID, exposureID, userID, exposuredom.StateInProgress, notes)
}

// SeverityChangeCall is one analyst's severity change of an exposure. An
// empty Severity removes the override (the reported severity applies again).
type SeverityChangeCall struct {
	TenantID   string
	ExposureID string
	UserID     string
	Severity   string
	Reason     string
	Audit      auditapp.AuditContext
}

// ChangeSeverity sets or removes the analyst severity override of an
// exposure. A reason is always required; the reported severity is kept, the
// peak severity read by the four-eyes disposition rule is never lowered, and
// every change is audited.
func (s *ExposureService) ChangeSeverity(ctx context.Context, in SeverityChangeCall) (*exposuredom.ExposureEvent, error) {
	if s.severities == nil {
		return nil, fmt.Errorf("exposure severity store not configured")
	}
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	exposureID, err := shared.IDFromString(in.ExposureID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	userID, err := shared.IDFromString(in.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: the acting user is required", shared.ErrValidation)
	}
	reason, err := exposuredom.NormalizeSeverityReason(in.Reason)
	if err != nil {
		return nil, err
	}
	var target exposuredom.Severity
	if in.Severity != "" {
		if target, err = exposuredom.ParseSeverity(in.Severity); err != nil {
			return nil, fmt.Errorf("%w: invalid severity", shared.ErrValidation)
		}
	}
	event, err := s.repo.GetByTenantAndID(ctx, tenantID, exposureID)
	if err != nil {
		return nil, err
	}
	if err := s.assertExposureScope(ctx, tenantID, event); err != nil {
		return nil, err
	}
	before := event.Severity()
	now := time.Now()
	if target == "" {
		err = event.RestoreReportedSeverity(reason, now)
	} else {
		err = event.OverrideSeverity(target, reason, userID, now)
	}
	if err != nil {
		return nil, err
	}
	if err := s.severities.SaveSeverity(ctx, event); err != nil {
		return nil, err
	}
	s.auditSeverity(ctx, in, event, before, reason)
	return event, nil
}

func (s *ExposureService) auditSeverity(ctx context.Context, in SeverityChangeCall, e *exposuredom.ExposureEvent, before exposuredom.Severity, reason string) {
	if s.audit == nil {
		return
	}
	actx := in.Audit
	if actx.TenantID == "" {
		actx.TenantID = in.TenantID
	}
	if actx.ActorID == "" {
		actx.ActorID = in.UserID
	}
	msg := "Exposure severity overridden"
	if !e.HasSeverityOverride() {
		msg = "Exposure severity override removed"
	}
	action := auditdom.ActionExposureSeverityChanged
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeExposure, e.ID().String()).
		WithResourceName(e.Title()).
		WithMessage(msg).
		WithMetadata("previous_severity", before.String()).
		WithMetadata("severity", e.Severity().String()).
		WithMetadata("reported_severity", e.SourceSeverity().String()).
		WithMetadata("override", e.HasSeverityOverride()).
		WithMetadata("reason", reason).
		WithSeverity(auditdom.SeverityForAction(action))
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit exposure severity change", "error", err)
	}
}

// categoryEventTypes expands display categories into their event types,
// intersected with already-selected types when there are any. An unknown
// category is a validation error, never silently dropped.
func categoryEventTypes(categories []string, selected []exposuredom.EventType) ([]exposuredom.EventType, error) {
	var out []exposuredom.EventType
	for _, raw := range categories {
		c, ok := exposuredom.ParseDisplayCategory(raw)
		if !ok {
			return nil, fmt.Errorf("%w: invalid category %q", shared.ErrValidation, raw)
		}
		for _, t := range exposuredom.EventTypesOf(c) {
			if len(selected) == 0 || slices.Contains(selected, t) {
				out = append(out, t)
			}
		}
	}
	if len(out) == 0 {
		// Nothing can match: a type that does not exist keeps the filter
		// closed instead of dropping it.
		out = []exposuredom.EventType{exposuredom.EventType("__none__")}
	}
	return out, nil
}

// CategoryCounts folds counts by event type into counts by display category.
func CategoryCounts(byEventType map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for t, n := range byEventType {
		out[string(exposuredom.EventType(t).Category())] += n
	}
	return out
}

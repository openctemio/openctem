// Package scanfreeze is the application service for scan freeze windows:
// CRUD with audit. Enforcement lives in the command claim predicate
// (postgres.freezeHoldPredicate) and the scan trigger (scan/freeze.go).
// Architecture: docs/architecture/scan-zones.md ("Freeze windows").
package scanfreeze

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	freezedom "github.com/openctemio/openctem/api/pkg/domain/scanfreeze"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service manages a tenant's freeze windows.
type Service struct {
	repo   freezedom.Repository
	audit  AuditLogger
	logger *logger.Logger
	now    func() time.Time
}

// NewService creates the service. audit may be nil (tests).
func NewService(repo freezedom.Repository, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{repo: repo, audit: audit, logger: log.With("service", "scan_freeze"), now: time.Now}
}

// CreateInput creates a window; ScanZoneID empty freezes the whole tenant.
type CreateInput struct {
	TenantID   string
	ScanZoneID string
	Spec       freezedom.Spec
	CreatedBy  string
}

// UpdateInput changes a window; nil fields keep their value. Changing the
// recurrence needs the fields of the new recurrence.
type UpdateInput struct {
	TenantID    string
	WindowID    string
	Name        *string
	Description *string
	Timezone    *string
	Recurrence  *freezedom.Recurrence
	StartsAt    *time.Time
	EndsAt      *time.Time
	Days        *[]int
	StartTime   *string
	EndTime     *string
	Enabled     *bool
}

// ListInput filters a list.
type ListInput struct {
	TenantID   string
	ScanZoneID string
	TenantWide bool
}

func parseTenant(tenantID string) (shared.ID, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return tid, nil
}

// parseWindow parses ids; a malformed window id cannot name a window of the
// tenant, so it is not found.
func parseWindow(tenantID, id string) (shared.ID, shared.ID, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return shared.ID{}, shared.ID{}, err
	}
	wid, err := shared.IDFromString(id)
	if err != nil {
		return tid, shared.ID{}, freezedom.ErrNotFound
	}
	return tid, wid, nil
}

// List returns the tenant's windows.
func (s *Service) List(ctx context.Context, in ListInput) ([]*freezedom.Window, error) {
	tid, err := parseTenant(in.TenantID)
	if err != nil {
		return nil, err
	}
	f := freezedom.Filter{TenantWide: in.TenantWide}
	if in.ScanZoneID != "" {
		zid, err := shared.IDFromString(in.ScanZoneID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid scan_zone_id", shared.ErrValidation)
		}
		f.ScanZoneID = &zid
	}
	return s.repo.List(ctx, tid, f)
}

// Get returns one window of the tenant.
func (s *Service) Get(ctx context.Context, tenantID, id string) (*freezedom.Window, error) {
	tid, wid, err := parseWindow(tenantID, id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, tid, wid)
}

// Create validates and stores a window. A zone of another tenant is not
// found (the composite foreign key refuses it).
func (s *Service) Create(ctx context.Context, in CreateInput, actx auditapp.AuditContext) (*freezedom.Window, error) {
	tid, err := parseTenant(in.TenantID)
	if err != nil {
		return nil, err
	}
	var zoneID *shared.ID
	if in.ScanZoneID != "" {
		zid, err := shared.IDFromString(in.ScanZoneID)
		if err != nil {
			return nil, freezedom.ErrZoneNotFound
		}
		zoneID = &zid
	}
	var createdBy *shared.ID
	if in.CreatedBy != "" {
		if uid, err := shared.IDFromString(in.CreatedBy); err == nil {
			createdBy = &uid
		}
	}
	w, err := freezedom.NewWindow(tid, zoneID, in.Spec, createdBy, s.now())
	if err != nil {
		return nil, err
	}
	n, err := s.repo.Count(ctx, tid)
	if err != nil {
		return nil, err
	}
	if n >= freezedom.MaxWindowsPerTenant {
		return nil, freezedom.ErrTooMany
	}
	if err := s.repo.Create(ctx, w); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanFreezeWindowCreated, auditdom.ResourceTypeScanFreezeWindow, w.ID.String()).
		WithResourceName(w.Name).
		WithMessage(fmt.Sprintf("Scan freeze window '%s' created", w.Name)).
		WithMetadata("window", describe(w)))
	return s.repo.GetByID(ctx, tid, w.ID)
}

// Update changes a window.
func (s *Service) Update(ctx context.Context, in UpdateInput, actx auditapp.AuditContext) (*freezedom.Window, error) {
	tid, wid, err := parseWindow(in.TenantID, in.WindowID)
	if err != nil {
		return nil, err
	}
	w, err := s.repo.GetByID(ctx, tid, wid)
	if err != nil {
		return nil, err
	}
	before := describe(w)
	spec := w.Spec()
	if in.Name != nil {
		spec.Name = *in.Name
	}
	if in.Description != nil {
		spec.Description = *in.Description
	}
	if in.Timezone != nil {
		spec.Timezone = *in.Timezone
	}
	if in.Recurrence != nil {
		spec.Recurrence = *in.Recurrence
	}
	if in.StartsAt != nil {
		spec.StartsAt = in.StartsAt
	}
	if in.EndsAt != nil {
		spec.EndsAt = in.EndsAt
	}
	if in.Days != nil {
		spec.Days = *in.Days
	}
	if in.StartTime != nil {
		spec.StartTime = *in.StartTime
	}
	if in.EndTime != nil {
		spec.EndTime = *in.EndTime
	}
	if in.Enabled != nil {
		spec.Enabled = *in.Enabled
	}
	if err := w.Update(spec, s.now()); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, w); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanFreezeWindowUpdated, auditdom.ResourceTypeScanFreezeWindow, w.ID.String()).
		WithResourceName(w.Name).
		WithMessage(fmt.Sprintf("Scan freeze window '%s' updated", w.Name)).
		WithMetadata("before", before).
		WithMetadata("after", describe(w)))
	return s.repo.GetByID(ctx, tid, w.ID)
}

// Delete removes a window.
func (s *Service) Delete(ctx context.Context, tenantID, id string, actx auditapp.AuditContext) error {
	tid, wid, err := parseWindow(tenantID, id)
	if err != nil {
		return err
	}
	w, err := s.repo.GetByID(ctx, tid, wid)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tid, wid); err != nil {
		return err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanFreezeWindowDeleted, auditdom.ResourceTypeScanFreezeWindow, w.ID.String()).
		WithResourceName(w.Name).
		WithMessage(fmt.Sprintf("Scan freeze window '%s' deleted", w.Name)).
		WithMetadata("window", describe(w)))
	return nil
}

// describe is the audit view of a window's settings.
func describe(w *freezedom.Window) map[string]any {
	out := map[string]any{
		"recurrence": string(w.Recurrence),
		"timezone":   w.Timezone,
		"enabled":    w.Enabled,
	}
	if w.ScanZoneID != nil {
		out["scan_zone_id"] = w.ScanZoneID.String()
	}
	if w.Recurrence == freezedom.RecurrenceOnce && w.StartsAt != nil && w.EndsAt != nil {
		out["starts_at"] = w.StartsAt.UTC().Format(time.RFC3339)
		out["ends_at"] = w.EndsAt.UTC().Format(time.RFC3339)
	} else {
		out["days"] = w.Days
		out["start_time"] = freezedom.FormatMinute(w.StartMinute)
		out["end_time"] = freezedom.FormatMinute(w.EndMinute)
	}
	return out
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to record audit event", "action", string(event.Action), "error", err)
	}
}

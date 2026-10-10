package scangov

// Approval requests on scan definitions and the run gate (requests.go,
// gate.go) need these collaborators, wired after construction.
//
// Threat model of requests: the requester never approves their own
// request; approvers are the organization's members holding scans:approve
// that the decisive rule allows (roles or named people); the one
// relaxation, an owner approving their own request when no other approver
// can, needs a fresh code from the owner's authenticator app and a reason,
// is audited high and announced. An emergency run needs an owner or
// administrator, step-up (route) and a reason, is time-boxed, audited
// critical and announced. Every query carries the tenant from the
// authenticated principal; another organization's request is 404. The gate
// fails closed: an unreadable mode, rule set or request refuses the run.

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ApproverDirectory lists the organization's scan approvers
// (*postgres.ScanApprovalRepository).
type ApproverDirectory interface {
	ScanApprovers(ctx context.Context, tenantID shared.ID) ([]scangov.Approver, error)
}

// TOTPVerifier checks a fresh authenticator code (a used code is refused).
type TOTPVerifier interface {
	VerifyFreshTOTP(ctx context.Context, userID, code string) error
}

// ScanSource builds what the rules read from a scan (*scan.Service).
type ScanSource interface {
	// GovernanceSubject loads the tenant's scan and its definition and facts.
	GovernanceSubject(ctx context.Context, tenantID, scanID shared.ID) (*scan.Scan, scangov.Definition, scangov.Facts, error)
	// GovernanceSubjectOf is the definition and facts of an unsaved scan.
	GovernanceSubjectOf(ctx context.Context, sc *scan.Scan) (scangov.Definition, scangov.Facts, error)
	// RunApproved starts a run of an approved scan as userID.
	RunApproved(ctx context.Context, tenantID, scanID shared.ID, userID string) error
}

// InAppNotifier delivers an in-app notification.
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// AuditLogger writes tenant audit events (*audit.AuditService).
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// SetRequests wires the request store. Without it the gate lets every run
// through only in Off; any other mode refuses (fail closed).
func (s *Service) SetRequests(repo scangov.Repository) { s.repo = repo }

// SetApprovers wires the approver directory and the authenticator check.
func (s *Service) SetApprovers(dir ApproverDirectory, totp TOTPVerifier) {
	s.approvers, s.totp = dir, totp
}

// SetScans wires the scan service.
func (s *Service) SetScans(src ScanSource) { s.scans = src }

// SetNotifier wires in-app notifications.
func (s *Service) SetNotifier(n InAppNotifier) { s.inApp = n }

// SetAudit wires the tenant audit log.
func (s *Service) SetAudit(a AuditLogger) { s.audit = a }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

func (s *Service) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// Actor is the authenticated caller.
type Actor struct {
	UserID       string
	AuditContext auditapp.AuditContext
}

// rules returns the mode in force and the organization's rules.
func (s *Service) rules(ctx context.Context, tenantID shared.ID) (scangov.Mode, tenant.ScanGovernanceSettings, error) {
	m, _, _, err := s.modes.EffectiveMode(ctx, tenantID)
	if err != nil {
		return "", tenant.ScanGovernanceSettings{}, fmt.Errorf("read scan approval mode: %w", err)
	}
	if m == scangov.ModeOff {
		return m, tenant.ScanGovernanceSettings{}, nil
	}
	st, err := s.settings.GetScanGovernanceSettings(ctx, tenantID.String())
	if err != nil {
		return "", tenant.ScanGovernanceSettings{}, fmt.Errorf("read scan approval rules: %w", err)
	}
	return m, *st, nil
}

// Evaluate applies the organization's rules to a definition's facts.
func (s *Service) Evaluate(ctx context.Context, tenantID shared.ID, f scangov.Facts) (scangov.Evaluation, error) {
	m, st, err := s.rules(ctx, tenantID)
	if err != nil {
		return scangov.Evaluation{}, err
	}
	return scangov.Evaluate(m, st.Rules, f), nil
}

// Preview evaluates an unsaved scan: what the New Scan review step shows.
func (s *Service) Preview(ctx context.Context, sc *scan.Scan) (scangov.Evaluation, error) {
	if s.scans == nil {
		return scangov.Evaluation{}, fmt.Errorf("%w: scans not wired", shared.ErrInternal)
	}
	_, f, err := s.scans.GovernanceSubjectOf(ctx, sc)
	if err != nil {
		return scangov.Evaluation{}, err
	}
	return s.Evaluate(ctx, sc.TenantID, f)
}

func (s *Service) requireRepo() error {
	if s.repo == nil {
		return fmt.Errorf("%w: scan approval requests not wired", shared.ErrInternal)
	}
	return nil
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	actx.TenantID = tenantID.String()
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.log.Warn("scan approval audit", "error", logger.SanitizeError(err))
	}
}

func (s *Service) notifyUser(ctx context.Context, tenantID shared.ID, userID, title, body, severity string, scanID shared.ID) {
	if s.inApp == nil {
		return
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return
	}
	sid := scanID
	if err := s.inApp.Notify(ctx, notificationdom.NotificationParams{
		TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
		NotificationType: notificationdom.TypeScanApproval, Title: title, Body: body, Severity: severity,
		ResourceType: "scan", ResourceID: &sid, URL: "/scans/approvals",
	}); err != nil {
		s.log.Warn("scan approval notification", "error", logger.SanitizeError(err))
	}
}

// oneLine trims s to one line of at most n bytes.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Package scangov is scan approval governance (RFC-072,
// docs/rfcs/RFC-072-scan-approval-governance.md): the organization's
// approval settings (the mode an owner chooses and the approval rules).
//
// Threat model. Scan approval is an organization's own control, opt-in,
// against a careless or compromised member running a scan the organization
// would not want. Turning it off or loosening the rules is the guarded
// direction: the mode is owner-only, the rules owner or administrator, both
// behind step-up re-authentication and a reason, audited at high severity.
// A platform administrator may force the mode (scanpolicy); a forced mode
// refuses the owner's change. Every read and write is the authenticated
// tenant's own settings section. Platform abuse controls (deny list, domain
// proof for platform sensors, exclusions, scope, act scope) are independent
// of this and stay on in every mode.
package scangov

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ModeSource answers an organization's mode in force (*scanpolicy.Service).
type ModeSource interface {
	EffectiveMode(ctx context.Context, tenantID shared.ID) (scangov.Mode, string, scangov.PlatformPolicy, error)
}

// SettingsStore reads and writes the organization's settings section
// (*tenant.TenantService).
type SettingsStore interface {
	GetScanGovernanceSettings(ctx context.Context, tenantID string) (*tenant.ScanGovernanceSettings, error)
	UpdateScanGovernanceSettings(ctx context.Context, tenantID string, change func(*tenant.ScanGovernanceSettings) error,
		action audit.Action, reason string, actx auditapp.AuditContext) (*tenant.ScanGovernanceSettings, error)
}

// Service is scan approval governance.
type Service struct {
	modes    ModeSource
	settings SettingsStore
	log      *logger.Logger

	// Requests and the run gate (wiring.go).
	repo      scangov.Repository
	approvers ApproverDirectory
	scans     ScanSource
	totp      TOTPVerifier
	inApp     InAppNotifier
	audit     AuditLogger
	now       func() time.Time
}

// NewService creates the service.
func NewService(modes ModeSource, settings SettingsStore, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{modes: modes, settings: settings, log: log.With("service", "scan_governance")}
}

// View is the organization's settings as the settings page shows them.
type View struct {
	Settings tenant.ScanGovernanceSettings
	// Mode in force and who decided it; Policy is the platform policy.
	Mode   scangov.Mode
	Source string
	Policy scangov.PlatformPolicy
}

// Settings returns the organization's settings and the mode in force.
func (s *Service) Settings(ctx context.Context, tenantID shared.ID) (*View, error) {
	st, err := s.settings.GetScanGovernanceSettings(ctx, tenantID.String())
	if err != nil {
		return nil, err
	}
	m, src, p, err := s.modes.EffectiveMode(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return &View{Settings: *st, Mode: m, Source: src, Policy: p}, nil
}

// SetMode changes the owner's choice (the route checked the owner role and
// step-up). A mode the platform policy overrides is refused. Turning the
// mode on with no rule seeds the Light preset, so On is never silently
// empty.
func (s *Service) SetMode(ctx context.Context, tenantID shared.ID, m scangov.Mode, reason string, actx auditapp.AuditContext) (*View, error) {
	if !m.Valid() {
		return nil, fmt.Errorf("%w: scan approval must be off, on or strict", shared.ErrValidation)
	}
	_, _, p, err := s.modes.EffectiveMode(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !scangov.TenantMayChoose(m, p) {
		return nil, scangov.ErrModeForced
	}
	_, err = s.settings.UpdateScanGovernanceSettings(ctx, tenantID.String(), func(st *tenant.ScanGovernanceSettings) error {
		st.Mode = m
		if m != scangov.ModeOff && len(st.Rules) == 0 {
			st.Rules = scangov.Preset(scangov.PresetLight)
		}
		return nil
	}, audit.ActionScanGovernanceModeChanged, reason, actx)
	if err != nil {
		return nil, err
	}
	return s.Settings(ctx, tenantID)
}

// RulesInput replaces the approval rules (and the pending expiry).
type RulesInput struct {
	Rules             []scangov.Rule
	PendingExpiryDays int
	Reason            string
}

// SetRules replaces the rules (the route checked an administrator and
// step-up).
func (s *Service) SetRules(ctx context.Context, tenantID shared.ID, in RulesInput, actx auditapp.AuditContext) (*View, error) {
	rules, err := scangov.Normalize(in.Rules)
	if err != nil {
		return nil, err
	}
	_, err = s.settings.UpdateScanGovernanceSettings(ctx, tenantID.String(), func(st *tenant.ScanGovernanceSettings) error {
		st.Rules, st.PendingExpiryDays = rules, in.PendingExpiryDays
		return nil
	}, audit.ActionScanGovernanceRulesUpdated, in.Reason, actx)
	if err != nil {
		return nil, err
	}
	return s.Settings(ctx, tenantID)
}

// Package scanpolicy serves the platform policy for scan approval (RFC-073,
// docs/rfcs/RFC-073-scan-approval-governance.md §5): a platform default and
// a per-organization override, set only by a platform administrator, that
// lets the organization choose its scan approval mode or forces one; and the
// effective mode of an organization (its owner's choice under that policy).
//
// Threat model: forcing Off removes approvals an organization's owner
// wanted; forcing On or Strict adds them. Either is an operator's explicit
// choice: super_admin with a fresh console authenticator code (checked by
// the handler) and a reason, written to the admin audit log at critical
// severity, the other platform administrators emailed and the
// organization's administrators told in-app. No tenant route reads the
// override's history or writes it. Reads fail closed: an unreadable policy
// or setting is an error, which the callers treat as the strictest answer
// (scope entries keep their approvals; a scan run is refused).
package scanpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions.
const (
	ActionDefaultChanged  = "platform.scan_approval_policy_changed"
	ActionTenantOverrides = "organization.scan_approval_policy_changed"
)

// Sources of an effective policy.
const (
	SourcePlatformDefault = "platform_default"
	SourceOrganization    = "organization_override"
)

// cacheTTL bounds how long a replica serves the platform default it read.
const cacheTTL = 15 * time.Second

// ErrVersionConflict: the platform default changed since it was read.
var ErrVersionConflict = fmt.Errorf("%w: the scan approval policy was changed by someone else; reload and try again", shared.ErrConflict)

// ErrNotFound: no platform default stored (tenant_controlled applies).
var ErrNotFound = errors.New("scan approval policy not stored")

// Repository persists the platform default (platform_settings) and the
// per-organization override (tenants.scan_approval_policy).
type Repository interface {
	GetDefault(ctx context.Context) (scangov.PlatformPolicy, int, error)
	SetDefault(ctx context.Context, p scangov.PlatformPolicy, expectedVersion int, by shared.ID, at time.Time) (int, error)
	GetOverride(ctx context.Context, tenantID shared.ID) (*scangov.PlatformPolicy, error)
	SetOverride(ctx context.Context, tenantID shared.ID, p *scangov.PlatformPolicy) error
}

// SettingsReader reads an organization's scan governance settings
// (*tenant.TenantService).
type SettingsReader interface {
	GetScanGovernanceSettings(ctx context.Context, tenantID string) (*tenant.ScanGovernanceSettings, error)
}

// AuditWriter writes admin audit rows (admin.AuditLogRepository).
type AuditWriter interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// AdminLister lists the active platform administrators (alert recipients).
type AdminLister interface {
	ListActive(ctx context.Context) ([]*admin.AdminUser, error)
}

// Mailer emails the other platform administrators (asynchronous).
type Mailer interface {
	NotifyScopePolicyChanged(ctx context.Context, recipients []string, subject, body string)
}

// TenantNotifier tells an organization's administrators in-app.
type TenantNotifier interface {
	NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body string)
}

// Service reads and changes the policy.
type Service struct {
	repo     Repository
	settings SettingsReader
	audit    AuditWriter
	admins   AdminLister
	mail     Mailer
	tenants  TenantNotifier
	log      *logger.Logger

	mu       sync.Mutex
	cached   *scangov.PlatformPolicy
	cachedV  int
	cachedAt time.Time
}

// NewService creates the service; every dependency but repo may be nil.
func NewService(repo Repository, audit AuditWriter, admins AdminLister, mail Mailer, tenants TenantNotifier, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, audit: audit, admins: admins, mail: mail, tenants: tenants, log: log.With("service", "scan_policy")}
}

// SetSettings wires the organization settings the effective mode reads.
// Without it every organization is Off unless the policy forces a mode.
func (s *Service) SetSettings(r SettingsReader) { s.settings = r }

// Default returns the platform default and its version (0: nothing stored,
// tenant_controlled).
func (s *Service) Default(ctx context.Context) (scangov.PlatformPolicy, int, error) {
	s.mu.Lock()
	if s.cached != nil && time.Since(s.cachedAt) < cacheTTL {
		p, v := *s.cached, s.cachedV
		s.mu.Unlock()
		return p, v, nil
	}
	s.mu.Unlock()
	p, v, err := s.repo.GetDefault(ctx)
	if errors.Is(err, ErrNotFound) {
		p, v, err = scangov.PolicyTenantControlled, 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	s.mu.Lock()
	s.cached, s.cachedV, s.cachedAt = &p, v, time.Now()
	s.mu.Unlock()
	return p, v, nil
}

// Policy returns an organization's platform policy and where it comes from.
func (s *Service) Policy(ctx context.Context, tenantID shared.ID) (scangov.PlatformPolicy, string, error) {
	o, err := s.repo.GetOverride(ctx, tenantID)
	if err != nil {
		return "", "", fmt.Errorf("read scan approval policy: %w", err)
	}
	if o != nil && o.Valid() {
		return *o, SourceOrganization, nil
	}
	p, _, err := s.Default(ctx)
	if err != nil {
		return "", "", fmt.Errorf("read scan approval policy: %w", err)
	}
	if !p.Valid() {
		return "", "", errors.New("read scan approval policy: invalid stored value")
	}
	return p, SourcePlatformDefault, nil
}

// EffectiveMode is the organization's scan approval mode in force (its
// owner's choice under the platform policy), who decided it
// (scangov.SourceOrganization or SourcePlatform), and the policy.
func (s *Service) EffectiveMode(ctx context.Context, tenantID shared.ID) (scangov.Mode, string, scangov.PlatformPolicy, error) {
	p, _, err := s.Policy(ctx, tenantID)
	if err != nil {
		return "", "", "", err
	}
	var chosen scangov.Mode
	if s.settings != nil {
		st, err := s.settings.GetScanGovernanceSettings(ctx, tenantID.String())
		if err != nil {
			return "", "", "", fmt.Errorf("read scan governance settings: %w", err)
		}
		if st != nil {
			chosen = st.EffectiveMode()
		}
	}
	m, src := scangov.Effective(chosen, p)
	return m, src, p, nil
}

// ScanGovernanceMode is EffectiveMode for the scope service: an unreadable
// policy or setting answers Strict (scope entries keep their approvals).
func (s *Service) ScanGovernanceMode(ctx context.Context, tenantID shared.ID) (scangov.Mode, string) {
	m, src, _, err := s.EffectiveMode(ctx, tenantID)
	if err != nil {
		s.log.Warn("scan governance unreadable; strict in force for scope entries", "error", logger.SanitizeError(err))
		return scangov.ModeStrict, scangov.SourcePlatform
	}
	return m, src
}

// Change describes who changes the policy and why.
type Change struct {
	Actor     *admin.AdminUser
	Reason    string
	IP        string
	UserAgent string
}

func (c Change) check() error {
	if c.Actor == nil {
		return fmt.Errorf("%w: a platform administrator changes the policy", shared.ErrForbidden)
	}
	if strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 1000 {
		return fmt.Errorf("%w: a reason (at most 1000 characters) is required", shared.ErrValidation)
	}
	return nil
}

// UpdateDefault changes the platform default. The caller checked super_admin
// and a fresh authenticator code.
func (s *Service) UpdateDefault(ctx context.Context, p scangov.PlatformPolicy, expectedVersion int, c Change) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if !p.Valid() {
		return 0, fmt.Errorf("%w: policy must be tenant_controlled, off, on or strict", shared.ErrValidation)
	}
	prev, _, err := s.Default(ctx)
	if err != nil {
		return 0, err
	}
	v, err := s.repo.SetDefault(ctx, p, expectedVersion, c.Actor.ID(), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.cached, s.cachedV, s.cachedAt = &p, v, time.Now()
	s.mu.Unlock()
	s.record(ctx, c, ActionDefaultChanged, nil, string(prev), string(p))
	s.mailOthers(ctx, c, "[Scans] Platform default for scan approval changed",
		fmt.Sprintf("%s changed the platform default for scan approval from %s to %s. Reason: %s",
			c.Actor.Email(), prev, p, strings.TrimSpace(c.Reason)))
	return v, nil
}

// UpdateOverride sets (nil: removes) an organization's override. The caller
// checked super_admin, a fresh authenticator code and that the
// organization exists.
func (s *Service) UpdateOverride(ctx context.Context, tenantID shared.ID, p *scangov.PlatformPolicy, c Change) error {
	if err := c.check(); err != nil {
		return err
	}
	if p != nil && !p.Valid() {
		return fmt.Errorf("%w: policy must be tenant_controlled, off, on, strict or null", shared.ErrValidation)
	}
	prevMode, _, _, _ := s.EffectiveMode(ctx, tenantID)
	prev, err := s.repo.GetOverride(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := s.repo.SetOverride(ctx, tenantID, p); err != nil {
		return err
	}
	next, _, _, _ := s.EffectiveMode(ctx, tenantID)
	s.record(ctx, c, ActionTenantOverrides, &tenantID, policyText(prev), policyText(p))
	s.mailOthers(ctx, c, "[Scans] Scan approval policy changed for an organization",
		fmt.Sprintf("%s changed the scan approval policy of organization %s from %s to %s (in effect: %s). Reason: %s",
			c.Actor.Email(), tenantID, policyText(prev), policyText(p), next, strings.TrimSpace(c.Reason)))
	if s.tenants != nil && prevMode != next {
		s.tenants.NotifyAdmins(ctx, tenantID, "Scan approval changed by your platform administrator",
			"Scan approval in your organization is now "+describeMode(next)+". Step-up, scope exclusions, ownership proof, the platform deny list, audit and notifications still apply.")
	}
	return nil
}

func policyText(p *scangov.PlatformPolicy) string {
	if p == nil {
		return "platform default"
	}
	return string(*p)
}

func describeMode(m scangov.Mode) string {
	switch m {
	case scangov.ModeOn:
		return "on: the organization's rules decide which scans need approval"
	case scangov.ModeStrict:
		return "strict: matched scans need two approvers, and scope entries need approval"
	}
	return "off: no scan needs approval"
}

// record writes the critical admin audit row and a WARN line for alerting.
func (s *Service) record(ctx context.Context, c Change, action string, tenantID *shared.ID, from, to string) {
	s.log.Warn("scan approval policy changed", "alert", "scan_approval_policy_changed",
		"admin_id", c.Actor.ID().String(), "from", logger.SanitizeValue(from), "to", logger.SanitizeValue(to))
	if s.audit == nil {
		return
	}
	resourceType := "platform_setting"
	if tenantID != nil {
		resourceType = "tenant"
	}
	entry := admin.NewAuditLogBuilder(c.Actor, action).
		Resource(resourceType, tenantID, scangov.PlatformPolicyKey).
		Context(c.IP, c.UserAgent).
		Request("PUT", "", map[string]any{"from": from, "to": to, "reason": strings.TrimSpace(c.Reason)}).
		Critical().
		Build()
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.audit.Create(actx, entry); err != nil {
		s.log.Error("write admin audit for scan approval policy change", "error", err)
	}
}

func (s *Service) mailOthers(ctx context.Context, c Change, subject, body string) {
	if s.admins == nil || s.mail == nil {
		return
	}
	others, err := s.admins.ListActive(ctx)
	if err != nil {
		s.log.Warn("list administrators for scan policy alert", "error", err)
		return
	}
	to := []string{}
	for _, o := range others {
		if o.ID() != c.Actor.ID() && o.Email() != "" {
			to = append(to, o.Email())
		}
	}
	if len(to) > 0 {
		s.mail.NotifyScopePolicyChanged(ctx, to, subject, body)
	}
}

// Override returns an organization's override (nil: the platform default).
func (s *Service) Override(ctx context.Context, tenantID shared.ID) (*scangov.PlatformPolicy, error) {
	return s.repo.GetOverride(ctx, tenantID)
}

// Package scopepolicy serves the platform policy for scope-widening
// approvals (RFC-054 §12.6): a platform default and a per-organization
// override, set only by a platform administrator.
//
// Threat model: approvals protect against a typo and against a single
// stolen session widening scope. Relaxing them is an operator's explicit
// choice: super_admin with a fresh console authenticator code (checked by
// the handler) and a reason, written to the admin audit log at critical
// severity, the other platform administrators emailed and the organization's
// administrators told in-app. No tenant route reads or writes it. Reads fail
// closed: when the policy cannot be read the mode is `required`.
package scopepolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions.
const (
	ActionDefaultChanged  = "platform.scope_approval_policy_changed"
	ActionTenantOverrides = "organization.scope_approval_policy_changed"
)

// Sources of an effective mode.
const (
	SourcePlatformDefault = "platform_default"
	SourceOrganization    = "organization_override"
)

// cacheTTL bounds how long a replica serves the platform default it read.
const cacheTTL = 15 * time.Second

// ErrVersionConflict: the platform default changed since it was read.
var ErrVersionConflict = fmt.Errorf("%w: the scope approval policy was changed by someone else; reload and try again", shared.ErrConflict)

// ErrNotFound: no platform default stored (the default `required` applies).
var ErrNotFound = errors.New("scope approval policy not stored")

// Repository persists the platform default (platform_settings) and the
// per-organization override (tenants.scope_approval_policy).
type Repository interface {
	GetDefault(ctx context.Context) (tenant.ScopeApprovalMode, int, error)
	SetDefault(ctx context.Context, mode tenant.ScopeApprovalMode, expectedVersion int, by shared.ID, at time.Time) (int, error)
	GetOverride(ctx context.Context, tenantID shared.ID) (*tenant.ScopeApprovalMode, error)
	SetOverride(ctx context.Context, tenantID shared.ID, mode *tenant.ScopeApprovalMode) error
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
	repo    Repository
	audit   AuditWriter
	admins  AdminLister
	mail    Mailer
	tenants TenantNotifier
	log     *logger.Logger

	mu       sync.Mutex
	cached   *tenant.ScopeApprovalMode
	cachedV  int
	cachedAt time.Time
}

// NewService creates the service; every dependency but repo may be nil.
func NewService(repo Repository, audit AuditWriter, admins AdminLister, mail Mailer, tenants TenantNotifier, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, audit: audit, admins: admins, mail: mail, tenants: tenants, log: log.With("service", "scope_policy")}
}

// Default returns the platform default and its version (0: nothing stored,
// `required`).
func (s *Service) Default(ctx context.Context) (tenant.ScopeApprovalMode, int, error) {
	s.mu.Lock()
	if s.cached != nil && time.Since(s.cachedAt) < cacheTTL {
		m, v := *s.cached, s.cachedV
		s.mu.Unlock()
		return m, v, nil
	}
	s.mu.Unlock()
	m, v, err := s.repo.GetDefault(ctx)
	if errors.Is(err, ErrNotFound) {
		m, v, err = tenant.ScopeApprovalRequired, 0, nil
	}
	if err != nil {
		return tenant.ScopeApprovalRequired, 0, err
	}
	s.mu.Lock()
	s.cached, s.cachedV, s.cachedAt = &m, v, time.Now()
	s.mu.Unlock()
	return m, v, nil
}

// Effective returns an organization's mode and where it comes from. Fail
// closed: any read error answers `required`.
func (s *Service) Effective(ctx context.Context, tenantID shared.ID) (tenant.ScopeApprovalMode, string) {
	o, err := s.repo.GetOverride(ctx, tenantID)
	if err != nil {
		s.log.Warn("scope approval policy unreadable; required in force", "error", logger.SanitizeError(err))
		return tenant.ScopeApprovalRequired, SourcePlatformDefault
	}
	if o != nil && o.Valid() {
		return *o, SourceOrganization
	}
	m, _, err := s.Default(ctx)
	if err != nil || !m.Valid() {
		s.log.Warn("scope approval policy unreadable; required in force", "error", logger.SanitizeError(err))
		return tenant.ScopeApprovalRequired, SourcePlatformDefault
	}
	return m, SourcePlatformDefault
}

// EffectiveScopeApprovalMode is Effective for the scope service.
func (s *Service) EffectiveScopeApprovalMode(ctx context.Context, tenantID shared.ID) (tenant.ScopeApprovalMode, string) {
	return s.Effective(ctx, tenantID)
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
func (s *Service) UpdateDefault(ctx context.Context, mode tenant.ScopeApprovalMode, expectedVersion int, c Change) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if !mode.Valid() {
		return 0, fmt.Errorf("%w: mode must be required, tenant_controlled or disabled", shared.ErrValidation)
	}
	prev, _, err := s.Default(ctx)
	if err != nil {
		return 0, err
	}
	v, err := s.repo.SetDefault(ctx, mode, expectedVersion, c.Actor.ID(), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.cached, s.cachedV, s.cachedAt = &mode, v, time.Now()
	s.mu.Unlock()
	s.record(ctx, c, ActionDefaultChanged, nil, string(prev), string(mode))
	s.mailOthers(ctx, c, "[Scope] Platform default for scope approvals changed",
		fmt.Sprintf("%s changed the platform default for scope-widening approvals from %s to %s. Reason: %s",
			c.Actor.Email(), prev, mode, strings.TrimSpace(c.Reason)))
	return v, nil
}

// UpdateOverride sets (nil: removes) an organization's override. The caller
// checked super_admin, a fresh authenticator code and that the
// organization exists.
func (s *Service) UpdateOverride(ctx context.Context, tenantID shared.ID, mode *tenant.ScopeApprovalMode, c Change) error {
	if err := c.check(); err != nil {
		return err
	}
	if mode != nil && !mode.Valid() {
		return fmt.Errorf("%w: mode must be required, tenant_controlled, disabled or null", shared.ErrValidation)
	}
	prevMode, _ := s.Effective(ctx, tenantID)
	prev, err := s.repo.GetOverride(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := s.repo.SetOverride(ctx, tenantID, mode); err != nil {
		return err
	}
	next, _ := s.Effective(ctx, tenantID)
	s.record(ctx, c, ActionTenantOverrides, &tenantID, modeText(prev), modeText(mode))
	s.mailOthers(ctx, c, "[Scope] Scope approval policy changed for an organization",
		fmt.Sprintf("%s changed the scope-widening approval policy of organization %s from %s to %s (in effect: %s). Reason: %s",
			c.Actor.Email(), tenantID, modeText(prev), modeText(mode), next, strings.TrimSpace(c.Reason)))
	if s.tenants != nil && prevMode != next {
		s.tenants.NotifyAdmins(ctx, tenantID, "Scope approval policy changed by your platform administrator",
			"Widening scope in your organization now follows the policy: "+describeMode(next)+". Step-up, the dry run, ownership proof, the platform deny list, audit and notifications still apply.")
	}
	return nil
}

func modeText(m *tenant.ScopeApprovalMode) string {
	if m == nil {
		return "platform default"
	}
	return string(*m)
}

func describeMode(m tenant.ScopeApprovalMode) string {
	switch m {
	case tenant.ScopeApprovalDisabled:
		return "no approval is needed"
	case tenant.ScopeApprovalTenantControlled:
		return "your owner sets the number of approvals for every tier"
	}
	return "approvals are required"
}

// record writes the critical admin audit row and a WARN line for alerting.
func (s *Service) record(ctx context.Context, c Change, action string, tenantID *shared.ID, from, to string) {
	s.log.Warn("scope approval policy changed", "alert", "scope_approval_policy_changed",
		"admin_id", c.Actor.ID().String(), "from", logger.SanitizeValue(from), "to", logger.SanitizeValue(to))
	if s.audit == nil {
		return
	}
	resourceName := tenant.ScopeApprovalPolicyKey
	resourceType := "platform_setting"
	if tenantID != nil {
		resourceType = "tenant"
	}
	entry := admin.NewAuditLogBuilder(c.Actor, action).
		Resource(resourceType, tenantID, resourceName).
		Context(c.IP, c.UserAgent).
		Request("PUT", "", map[string]any{"from": from, "to": to, "reason": strings.TrimSpace(c.Reason)}).
		Critical().
		Build()
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.audit.Create(actx, entry); err != nil {
		s.log.Error("write admin audit for scope approval policy change", "error", err)
	}
}

func (s *Service) mailOthers(ctx context.Context, c Change, subject, body string) {
	if s.admins == nil || s.mail == nil {
		return
	}
	others, err := s.admins.ListActive(ctx)
	if err != nil {
		s.log.Warn("list administrators for scope policy alert", "error", err)
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
func (s *Service) Override(ctx context.Context, tenantID shared.ID) (*tenant.ScopeApprovalMode, error) {
	return s.repo.GetOverride(ctx, tenantID)
}

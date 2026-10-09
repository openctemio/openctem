// Package entitlement answers what an organization may add under its plan:
// the effective limits (plan default, or an administrator's override), the
// usage behind them, and the one check every creation path calls
// (docs/architecture/plans-and-limits.md).
//
// Check is fail-closed: when the plan, overrides or usage cannot be read, the
// addition is refused. A limit never removes anything that exists.
package entitlement

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions.
const (
	ActionDefaultsChanged  = "platform.plan_defaults_changed"
	ActionTenantPlanSet    = "organization.plan_set"
	ActionOverrideSet      = "organization.plan_override_set"
	ActionOverrideRemoved  = "organization.plan_override_removed"
	AlertDefaultsChanged   = "plan_defaults_changed"
	defaultsCacheTTL       = 15 * time.Second
	maxOverrideReasonRunes = 500
)

// ChangeNotifier tells the other administrators about a change to the plan
// defaults (asynchronous).
type ChangeNotifier interface {
	NotifyPlanDefaultsChanged(ctx context.Context, adminEmail string, recipients []string) error
}

// AuditWriter writes one admin audit row.
type AuditWriter interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// AdminLister lists the active administrators.
type AdminLister interface {
	ListActive(ctx context.Context) ([]*admin.AdminUser, error)
}

// Service serves limits and checks.
type Service struct {
	repo     plan.Repository
	audit    AuditWriter
	admins   AdminLister
	notifier ChangeNotifier
	log      *logger.Logger
	now      func() time.Time

	mu       sync.Mutex
	cached   plan.Defaults
	version  int
	cachedAt time.Time

	// Module entitlements (modules.go).
	modules         plan.ModuleRepository
	modulesChanged  ModulesChangeNotifier
	cachedModules   plan.PlanModules
	modulesVersion  int
	modulesCachedAt time.Time
}

// NewService creates the service. audit, admins and notifier may be nil.
func NewService(repo plan.Repository, audit AuditWriter, admins AdminLister, notifier ChangeNotifier, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, audit: audit, admins: admins, notifier: notifier,
		log: log.With("service", "entitlement"), now: time.Now}
}

// SetNotifier wires the administrator notification.
func (s *Service) SetNotifier(n ChangeNotifier) { s.notifier = n }

// Defaults returns the plan defaults (built-in until an administrator saves
// them) and their version (0: not stored yet).
func (s *Service) Defaults(ctx context.Context) (plan.Defaults, int, error) {
	s.mu.Lock()
	if s.cached != nil && s.now().Sub(s.cachedAt) < defaultsCacheTTL {
		d, v := s.cached, s.version
		s.mu.Unlock()
		return d, v, nil
	}
	s.mu.Unlock()
	d, v, err := s.repo.GetDefaults(ctx)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			return nil, 0, err
		}
		d, v = plan.BuiltinDefaults(), 0
	}
	s.mu.Lock()
	s.cached, s.version, s.cachedAt = d, v, s.now()
	s.mu.Unlock()
	return d, v, nil
}

// PlanOf returns the organization's plan: Enterprise when none is stored (an
// organization created before plans).
func (s *Service) PlanOf(ctx context.Context, tenantID shared.ID) (plan.Plan, error) {
	p, ok, err := s.repo.TenantPlan(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if !ok {
		return plan.Enterprise, nil
	}
	return p, nil
}

// Summary is an organization's plan, limits and usage.
type Summary struct {
	Plan      plan.Plan        `json:"plan"`
	Limits    []plan.Effective `json:"limits"`
	OverLimit bool             `json:"over_limit"`
}

// Effective returns the organization's limits with their usage.
func (s *Service) Effective(ctx context.Context, tenantID shared.ID) (*Summary, error) {
	p, err := s.PlanOf(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defaults, _, err := s.Defaults(ctx)
	if err != nil {
		return nil, err
	}
	overrides, err := s.repo.ListOverrides(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	usage, err := s.repo.Usage(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	byKey := map[plan.Key]plan.Override{}
	for _, o := range overrides {
		if o.Active(now) {
			byKey[o.Key] = o
		}
	}
	sum := &Summary{Plan: p, Limits: make([]plan.Effective, 0, len(plan.Keys))}
	base := defaults.For(p)
	for _, k := range plan.Keys {
		e := plan.Effective{Key: k, Limit: base.Get(k), Source: plan.SourcePlan, Used: usage[k]}
		if o, ok := byKey[k]; ok {
			e.Limit, e.Source, e.ExpiresAt, e.Reason = o.Value, plan.SourceOverride, o.ExpiresAt, o.Reason
		}
		e.OverLimit = e.Limit != plan.Unlimited && e.Used > e.Limit
		sum.OverLimit = sum.OverLimit || e.OverLimit
		sum.Limits = append(sum.Limits, e)
	}
	return sum, nil
}

// Check refuses an addition of delta to key when it would exceed the
// organization's limit: *plan.ErrLimitReached. Any read error refuses too
// (fail-closed). Unlimited never refuses.
func (s *Service) Check(ctx context.Context, tenantID shared.ID, key plan.Key, delta int) error {
	if !key.IsValid() {
		return plan.ErrInvalid
	}
	sum, err := s.Effective(ctx, tenantID)
	if err != nil {
		s.log.Warn("plan limit check failed; refusing (fail-closed)", "key", string(key), "error", err)
		return &plan.ErrLimitReached{Key: key, Unavailable: true}
	}
	for _, e := range sum.Limits {
		if e.Key != key {
			continue
		}
		if e.Limit == plan.Unlimited || e.Used+delta <= e.Limit {
			return nil
		}
		refusals.WithLabelValues(string(key)).Inc()
		return &plan.ErrLimitReached{Key: key, Limit: e.Limit, Used: e.Used}
	}
	return nil
}

// CheckFreeTeam refuses a new Free organization for a user who already owns
// the Free plan's free_teams_per_user.
func (s *Service) CheckFreeTeam(ctx context.Context, userID shared.ID) error {
	defaults, _, err := s.Defaults(ctx)
	if err != nil {
		return &plan.ErrLimitReached{Key: plan.FreeTeamsPerUser, Unavailable: true}
	}
	limit := defaults.For(plan.Free).Get(plan.FreeTeamsPerUser)
	if limit == plan.Unlimited {
		return nil
	}
	n, err := s.repo.CountOwnedFreeTenants(ctx, userID)
	if err != nil {
		return &plan.ErrLimitReached{Key: plan.FreeTeamsPerUser, Limit: limit, Unavailable: true}
	}
	if n+1 > limit {
		refusals.WithLabelValues(string(plan.FreeTeamsPerUser)).Inc()
		return &plan.ErrLimitReached{Key: plan.FreeTeamsPerUser, Limit: limit, Used: n}
	}
	return nil
}

// AssignFree records a new self-service organization as Free.
func (s *Service) AssignFree(ctx context.Context, tenantID shared.ID) error {
	return s.repo.SetTenantPlan(ctx, tenantID, plan.Free, nil, s.now().UTC())
}

// UpdateDefaults saves the plan defaults (the caller checked super admin and
// a fresh authenticator code). Audited at critical severity; the other
// administrators are told.
func (s *Service) UpdateDefaults(ctx context.Context, actor *admin.AdminUser, d plan.Defaults, expectedVersion int, ip, ua string) (int, error) {
	if actor == nil {
		return 0, errors.New("plan defaults change needs an administrator")
	}
	if err := d.Validate(); err != nil {
		return 0, err
	}
	v, err := s.repo.SaveDefaults(ctx, d, expectedVersion, actor.ID(), s.now().UTC())
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.cached, s.version, s.cachedAt = d, v, s.now()
	s.mu.Unlock()
	body := map[string]any{"version": v}
	for p, l := range d {
		body[string(p)] = l
	}
	s.writeAudit(ctx, actor, ActionDefaultsChanged, nil, "plan_limits", body, ip, ua)
	recipients := []string{}
	if s.admins != nil {
		if others, lerr := s.admins.ListActive(ctx); lerr == nil {
			for _, o := range others {
				if o.ID() != actor.ID() {
					recipients = append(recipients, o.Email())
				}
			}
		}
	}
	s.log.Warn("plan defaults changed", "alert", AlertDefaultsChanged, "admin_id", actor.ID().String(), "notified", len(recipients))
	if s.notifier != nil && len(recipients) > 0 {
		if nerr := s.notifier.NotifyPlanDefaultsChanged(ctx, actor.Email(), recipients); nerr != nil {
			s.log.Warn("notify administrators of plan defaults change", "error", nerr)
		}
	}
	return v, nil
}

// ChangeTenantPlan changes an organization's plan (audited).
func (s *Service) ChangeTenantPlan(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, p plan.Plan, ip, ua string) error {
	if !p.IsValid() {
		return plan.ErrInvalid
	}
	id := actor.ID()
	lost, regained, err := s.lostAndRegained(ctx, tenantID, func() error {
		return s.repo.SetTenantPlan(ctx, tenantID, p, &id, s.now().UTC())
	})
	if err != nil {
		return err
	}
	s.applyGrace(ctx, tenantID, lost, regained)
	s.writeAudit(ctx, actor, ActionTenantPlanSet, &tenantID, "tenant", map[string]any{"plan": string(p)}, ip, ua)
	// The plan decides the organization's modules: refresh them.
	if s.modulesChanged != nil {
		s.modulesChanged(tenantID.String())
	}
	return nil
}

// OverrideInput is one per-organization limit.
type OverrideInput struct {
	Key       plan.Key
	Value     int
	Reason    string
	ExpiresAt *time.Time
}

// PutOverride sets one per-organization limit (audited). A reason is required;
// an expiry, when given, must be in the future.
func (s *Service) PutOverride(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, in OverrideInput, ip, ua string) error {
	reason := strings.TrimSpace(in.Reason)
	now := s.now().UTC()
	if !in.Key.IsValid() || in.Value < plan.Unlimited || reason == "" || len([]rune(reason)) > maxOverrideReasonRunes ||
		(in.ExpiresAt != nil && !in.ExpiresAt.After(now)) {
		return plan.ErrInvalid
	}
	id := actor.ID()
	o := plan.Override{TenantID: tenantID, Key: in.Key, Value: in.Value, Reason: reason, ExpiresAt: in.ExpiresAt, SetBy: &id, SetAt: now}
	if err := s.repo.SetOverride(ctx, o); err != nil {
		return err
	}
	body := map[string]any{"key": string(in.Key), "value": in.Value, "reason": reason}
	if in.ExpiresAt != nil {
		body["expires_at"] = in.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.writeAudit(ctx, actor, ActionOverrideSet, &tenantID, "tenant", body, ip, ua)
	return nil
}

// DeleteOverride removes one per-organization limit (audited).
func (s *Service) DeleteOverride(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, key plan.Key, ip, ua string) error {
	if !key.IsValid() {
		return plan.ErrInvalid
	}
	if err := s.repo.DeleteOverride(ctx, tenantID, key); err != nil {
		return err
	}
	s.writeAudit(ctx, actor, ActionOverrideRemoved, &tenantID, "tenant", map[string]any{"key": string(key)}, ip, ua)
	return nil
}

func (s *Service) writeAudit(ctx context.Context, actor *admin.AdminUser, action string, id *shared.ID, resource string, body map[string]any, ip, ua string) {
	if s.audit == nil || actor == nil {
		return
	}
	b := admin.NewAuditLogBuilder(actor, action).
		Resource(resource, id, "").
		Context(ip, ua).
		Request("PUT", "", body)
	// A change to every organization's limits is critical; one
	// organization's plan or override is high.
	if action == ActionDefaultsChanged || action == ActionPlanModulesChanged {
		b = b.Critical()
	} else {
		b = b.High()
	}
	entry := b.Build()
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.audit.Create(actx, entry); err != nil {
		s.log.Error("write admin audit", "action", action, "error", err)
	}
}

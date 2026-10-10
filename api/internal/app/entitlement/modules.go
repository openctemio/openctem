package entitlement

// Module entitlements (RFC-064): which modules an organization may use. The
// plan decides (the plan to module map, every module until an administrator
// narrows it); an administrator's grant adds a module and a deny removes one.
// Core modules are always entitled. The module service reads Entitled for
// every route gate, job and console list; a read error is reported, never
// turned into "entitled" (fail-closed).

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Admin audit actions of module entitlements.
const (
	ActionPlanModulesChanged = "platform.plan_modules_changed"
	ActionModuleGrantSet     = "organization.module_grant_set"
	ActionModuleGrantRemoved = "organization.module_grant_removed"
)

// Entitlement sources.
const (
	SourceCore  = "core"
	SourcePlan  = "plan"
	SourceGrant = "grant"
	SourceDeny  = "deny"
	SourceNone  = "none" // the plan does not include it and nothing grants it
)

// ModulesChangeNotifier is told when entitlements change so every cache of
// the module state drops the organization ("" = every organization).
type ModulesChangeNotifier func(tenantID string)

// SetModuleRepository wires module entitlements. Without it every module is
// entitled (no plan mapping, no grants).
func (s *Service) SetModuleRepository(r plan.ModuleRepository) { s.modules = r }

// SetModulesChangeNotifier wires the cache invalidation of the module state.
func (s *Service) SetModulesChangeNotifier(n ModulesChangeNotifier) { s.modulesChanged = n }

// PlanModules returns the plan to module map (every module for every plan
// until an administrator saves one) and its version (0: not stored).
func (s *Service) PlanModules(ctx context.Context) (plan.PlanModules, int, error) {
	if s.modules == nil {
		return plan.BuiltinPlanModules(), 0, nil
	}
	s.mu.Lock()
	if s.cachedModules != nil && s.now().Sub(s.modulesCachedAt) < defaultsCacheTTL {
		m, v := s.cachedModules, s.modulesVersion
		s.mu.Unlock()
		return m, v, nil
	}
	s.mu.Unlock()
	m, v, err := s.modules.GetPlanModules(ctx)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			return nil, 0, err
		}
		m, v = plan.BuiltinPlanModules(), 0
	}
	s.mu.Lock()
	s.cachedModules, s.modulesVersion, s.modulesCachedAt = m, v, s.now()
	s.mu.Unlock()
	return m, v, nil
}

// ModuleEntitlement is one module's entitlement for one organization.
type ModuleEntitlement struct {
	Module         string     `json:"module"`
	Name           string     `json:"name"`
	Core           bool       `json:"core"`
	Entitled       bool       `json:"entitled"`
	Source         string     `json:"source"`
	InPlan         bool       `json:"in_plan"`
	GrantReason    string     `json:"grant_reason,omitempty"`
	GrantExpiresAt *time.Time `json:"grant_expires_at,omitempty"`
}

// ModuleEntitlements returns every top-level module of the registry with the
// organization's entitlement and its source.
func (s *Service) ModuleEntitlements(ctx context.Context, tenantID shared.ID) (plan.Plan, []ModuleEntitlement, error) {
	p, err := s.PlanOf(ctx, tenantID)
	if err != nil {
		return "", nil, err
	}
	pm, _, err := s.PlanModules(ctx)
	if err != nil {
		return "", nil, err
	}
	grants := map[string]plan.ModuleGrant{}
	if s.modules != nil {
		list, lerr := s.modules.ListModuleGrants(ctx, tenantID)
		if lerr != nil {
			return "", nil, lerr
		}
		now := s.now()
		for _, g := range list {
			if g.Active(now) {
				grants[g.ModuleID] = g
			}
		}
	}
	out := make([]ModuleEntitlement, 0, len(moduledom.Registry))
	for _, d := range moduledom.Registry {
		if d.Parent != "" {
			continue // a sub-module follows its parent
		}
		e := ModuleEntitlement{Module: d.ID, Name: d.Name, Core: d.Core, InPlan: pm.Includes(p, d.ID)}
		g, granted := grants[d.ID]
		switch {
		case d.Core:
			e.Entitled, e.Source = true, SourceCore
		case granted && g.Kind == plan.GrantDeny:
			e.Entitled, e.Source = false, SourceDeny
		case granted && g.Kind == plan.GrantAdd:
			e.Entitled, e.Source = true, SourceGrant
		case e.InPlan:
			e.Entitled, e.Source = true, SourcePlan
		default:
			e.Entitled, e.Source = false, SourceNone
		}
		if granted && !d.Core {
			e.GrantReason, e.GrantExpiresAt = g.Reason, g.ExpiresAt
		}
		out = append(out, e)
	}
	return p, out, nil
}

// NotEntitled returns the modules the organization may not use: top-level
// modules and their sub-modules. An error means the entitlement could not be
// read; the caller treats every non-core module as unavailable.
func (s *Service) NotEntitled(ctx context.Context, tenantID string) (map[string]bool, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, err
	}
	_, list, err := s.ModuleEntitlements(ctx, id)
	if err != nil {
		return nil, err
	}
	off := map[string]bool{}
	for _, e := range list {
		if !e.Entitled {
			off[e.Module] = true
		}
	}
	for _, d := range moduledom.Registry {
		if d.Parent != "" && off[d.Parent] {
			off[d.ID] = true
		}
	}
	return off, nil
}

// UpdatePlanModules saves the plan to module map (the caller checked super
// admin and a fresh authenticator code). Audited at critical severity; every
// organization's module state is refreshed.
func (s *Service) UpdatePlanModules(ctx context.Context, actor *admin.AdminUser, m plan.PlanModules, expectedVersion int, ip, ua string) (int, error) {
	if actor == nil {
		return 0, errors.New("plan modules change needs an administrator")
	}
	if s.modules == nil {
		return 0, errors.New("module entitlements are not configured")
	}
	if err := m.Validate(); err != nil {
		return 0, err
	}
	m = m.Normalized()
	v, err := s.modules.SavePlanModules(ctx, m, expectedVersion, actor.ID(), s.now().UTC())
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.cachedModules, s.modulesVersion, s.modulesCachedAt = m, v, s.now()
	s.mu.Unlock()
	body := map[string]any{"version": v}
	for p, ids := range m {
		body[string(p)] = ids
	}
	s.writeAudit(ctx, actor, ActionPlanModulesChanged, nil, "plan_modules", body, ip, ua)
	s.log.Warn("plan modules changed", "alert", ActionPlanModulesChanged, "admin_id", actor.ID().String())
	if s.modulesChanged != nil {
		s.modulesChanged("")
	}
	return v, nil
}

// ModuleGrantInput is one per-organization grant or deny.
type ModuleGrantInput struct {
	Module    string
	Kind      plan.GrantKind
	Reason    string
	ExpiresAt *time.Time
}

// Validate reports plan.ErrInvalid unless the input names a top-level,
// non-core module, grant or deny, a reason and, if any, an expiry after now.
// Handlers call it before asking for a step-up code, so a typo does not
// spend the code.
func (in ModuleGrantInput) Validate(now time.Time) error {
	d, known := moduledom.Lookup(in.Module)
	if !known || d.Core || d.Parent != "" || !in.Kind.IsValid() || !ValidGrantReason(in.Reason) ||
		(in.ExpiresAt != nil && !in.ExpiresAt.After(now)) {
		return plan.ErrInvalid
	}
	return nil
}

// ValidGrantReason reports a non-blank reason of at most 500 characters.
func ValidGrantReason(reason string) bool {
	r := strings.TrimSpace(reason)
	return r != "" && len([]rune(r)) <= maxOverrideReasonRunes
}

// PutModuleGrant sets one organization's grant or deny of a top-level,
// non-core module (audited). A reason is required; an expiry, when given,
// must be in the future. The HTTP layer requires a step-up code first.
func (s *Service) PutModuleGrant(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, in ModuleGrantInput, ip, ua string) error {
	if s.modules == nil {
		return errors.New("module entitlements are not configured")
	}
	reason := strings.TrimSpace(in.Reason)
	now := s.now().UTC()
	if err := in.Validate(now); err != nil {
		return err
	}
	id := actor.ID()
	g := plan.ModuleGrant{TenantID: tenantID, ModuleID: in.Module, Kind: in.Kind, Reason: reason,
		ExpiresAt: in.ExpiresAt, SetBy: &id, SetAt: now}
	if err := s.modules.SetModuleGrant(ctx, g); err != nil {
		return err
	}
	body := map[string]any{"module": in.Module, "kind": string(in.Kind), "reason": reason}
	if in.ExpiresAt != nil {
		body["expires_at"] = in.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.writeAudit(ctx, actor, ActionModuleGrantSet, &tenantID, "tenant", body, ip, ua)
	if s.modulesChanged != nil {
		s.modulesChanged(tenantID.String())
	}
	return nil
}

// DeleteModuleGrant removes one organization's grant or deny (audited with
// the reason). The HTTP layer requires a step-up code first.
func (s *Service) DeleteModuleGrant(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, moduleID, reason string, ip, ua string) error {
	if s.modules == nil {
		return errors.New("module entitlements are not configured")
	}
	if _, known := moduledom.Lookup(moduleID); !known || !ValidGrantReason(reason) {
		return plan.ErrInvalid
	}
	if err := s.modules.DeleteModuleGrant(ctx, tenantID, moduleID); err != nil {
		return err
	}
	s.writeAudit(ctx, actor, ActionModuleGrantRemoved, &tenantID, "tenant", map[string]any{"module": moduleID, "reason": strings.TrimSpace(reason)}, ip, ua)
	if s.modulesChanged != nil {
		s.modulesChanged(tenantID.String())
	}
	return nil
}

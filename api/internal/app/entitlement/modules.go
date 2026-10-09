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
	SourceNone  = "none"  // the plan does not include it and nothing grants it
	SourceGrace = "grace" // lost recently: read-only until ReadOnlyUntil
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
	// ReadOnlyUntil: the organization lost the module and keeps read access
	// (and export) until then; writes are refused and its jobs are stopped.
	ReadOnlyUntil *time.Time `json:"read_only_until,omitempty"`
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
	now := s.now()
	grants := map[string]plan.ModuleGrant{}
	// An expired trial grant gives read-only grace from its expiry.
	expiredGrant := map[string]time.Time{}
	grace := map[string]time.Time{}
	if s.modules != nil {
		list, lerr := s.modules.ListModuleGrants(ctx, tenantID)
		if lerr != nil {
			return "", nil, lerr
		}
		for _, g := range list {
			switch {
			case g.Active(now):
				grants[g.ModuleID] = g
			case g.Kind == plan.GrantAdd && g.ExpiresAt != nil:
				expiredGrant[g.ModuleID] = g.ExpiresAt.Add(plan.GracePeriod)
			}
		}
		if grace, lerr = s.modules.ListModuleGrace(ctx, tenantID); lerr != nil {
			return "", nil, lerr
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
		if !e.Entitled {
			until, ok := grace[d.ID]
			if t, eok := expiredGrant[d.ID]; eok && (!ok || t.After(until)) {
				until, ok = t, true
			}
			if ok && now.Before(until) {
				u := until
				e.Source, e.ReadOnlyUntil = SourceGrace, &u
			}
		}
		out = append(out, e)
	}
	return p, out, nil
}

// NotEntitled returns the modules the organization may not use: top-level
// modules and their sub-modules. The value is the end of the read-only grace
// (nil: no access at all). An error means the entitlement could not be read;
// the caller treats every non-core module as unavailable.
func (s *Service) NotEntitled(ctx context.Context, tenantID string) (map[string]*time.Time, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, err
	}
	_, list, err := s.ModuleEntitlements(ctx, id)
	if err != nil {
		return nil, err
	}
	off := map[string]*time.Time{}
	for _, e := range list {
		if !e.Entitled {
			off[e.Module] = e.ReadOnlyUntil
		}
	}
	for _, d := range moduledom.Registry {
		if until, ok := off[d.Parent]; ok && d.Parent != "" {
			off[d.ID] = until
		}
	}
	return off, nil
}

// lostAndRegained runs change and returns the top-level modules the
// organization lost and regained by it (grace aside). When the entitlement
// cannot be read around the change, no grace is started: the change stands.
func (s *Service) lostAndRegained(ctx context.Context, tenantID shared.ID, change func() error) (lost, regained []string, err error) {
	before := s.entitledSet(ctx, tenantID)
	if err := change(); err != nil {
		return nil, nil, err
	}
	if before == nil {
		return nil, nil, nil
	}
	after := s.entitledSet(ctx, tenantID)
	if after == nil {
		return nil, nil, nil
	}
	for id := range before {
		if !after[id] {
			lost = append(lost, id)
		}
	}
	for id := range after {
		if !before[id] {
			regained = append(regained, id)
		}
	}
	return lost, regained, nil
}

// entitledSet returns the non-core modules the organization is entitled to,
// or nil when the entitlement cannot be read (logged).
func (s *Service) entitledSet(ctx context.Context, tenantID shared.ID) map[string]bool {
	_, list, err := s.ModuleEntitlements(ctx, tenantID)
	if err != nil {
		s.log.Error("read module entitlements for grace", "tenant_id", tenantID.String(), "error", err)
		return nil
	}
	set := map[string]bool{}
	for _, e := range list {
		if e.Entitled && !e.Core {
			set[e.Module] = true
		}
	}
	return set
}

// applyGrace starts read-only grace for lost modules and ends it for
// regained ones. Best effort: a failure is logged, the change stands.
func (s *Service) applyGrace(ctx context.Context, tenantID shared.ID, lost, regained []string) {
	if s.modules == nil {
		return
	}
	if err := s.modules.StartModuleGrace(ctx, tenantID, lost, s.now().UTC().Add(plan.GracePeriod)); err != nil {
		s.log.Error("start module grace", "tenant_id", tenantID.String(), "error", err)
	}
	if err := s.modules.EndModuleGrace(ctx, tenantID, regained); err != nil {
		s.log.Error("end module grace", "tenant_id", tenantID.String(), "error", err)
	}
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
	old, _, oerr := s.PlanModules(ctx)
	v, err := s.modules.SavePlanModules(ctx, m, expectedVersion, actor.ID(), s.now().UTC())
	if err != nil {
		return 0, err
	}
	if oerr == nil {
		s.applyPlanGrace(ctx, old, m)
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

// PutModuleGrant sets one organization's grant or deny of a top-level,
// non-core module (audited). A reason is required; an expiry, when given,
// must be in the future.
func (s *Service) PutModuleGrant(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, in ModuleGrantInput, ip, ua string) error {
	if s.modules == nil {
		return errors.New("module entitlements are not configured")
	}
	reason := strings.TrimSpace(in.Reason)
	now := s.now().UTC()
	d, known := moduledom.Lookup(in.Module)
	if !known || d.Core || d.Parent != "" || !in.Kind.IsValid() || reason == "" ||
		len([]rune(reason)) > maxOverrideReasonRunes || (in.ExpiresAt != nil && !in.ExpiresAt.After(now)) {
		return plan.ErrInvalid
	}
	id := actor.ID()
	g := plan.ModuleGrant{TenantID: tenantID, ModuleID: in.Module, Kind: in.Kind, Reason: reason,
		ExpiresAt: in.ExpiresAt, SetBy: &id, SetAt: now}
	lost, regained, err := s.lostAndRegained(ctx, tenantID, func() error { return s.modules.SetModuleGrant(ctx, g) })
	if err != nil {
		return err
	}
	s.applyGrace(ctx, tenantID, lost, regained)
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

// DeleteModuleGrant removes one organization's grant or deny (audited).
func (s *Service) DeleteModuleGrant(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, moduleID string, ip, ua string) error {
	if s.modules == nil {
		return errors.New("module entitlements are not configured")
	}
	if _, known := moduledom.Lookup(moduleID); !known {
		return plan.ErrInvalid
	}
	lost, regained, err := s.lostAndRegained(ctx, tenantID, func() error {
		return s.modules.DeleteModuleGrant(ctx, tenantID, moduleID)
	})
	if err != nil {
		return err
	}
	s.applyGrace(ctx, tenantID, lost, regained)
	s.writeAudit(ctx, actor, ActionModuleGrantRemoved, &tenantID, "tenant", map[string]any{"module": moduleID}, ip, ua)
	if s.modulesChanged != nil {
		s.modulesChanged(tenantID.String())
	}
	return nil
}

// applyPlanGrace starts read-only grace for the organizations of each plan
// that lost a module, and ends it where a plan includes the module again.
func (s *Service) applyPlanGrace(ctx context.Context, old, next plan.PlanModules) {
	until := s.now().UTC().Add(plan.GracePeriod)
	for _, p := range plan.All {
		var lost, regained []string
		for _, d := range moduledom.Registry {
			if d.Core || d.Parent != "" {
				continue
			}
			was, is := old.Includes(p, d.ID), next.Includes(p, d.ID)
			switch {
			case was && !is:
				lost = append(lost, d.ID)
			case !was && is:
				regained = append(regained, d.ID)
			}
		}
		if err := s.modules.StartPlanModuleGrace(ctx, p, lost, until); err != nil {
			s.log.Error("start plan module grace", "plan", string(p), "error", err)
		}
		if err := s.modules.EndPlanModuleGrace(ctx, p, regained); err != nil {
			s.log.Error("end plan module grace", "plan", string(p), "error", err)
		}
	}
}

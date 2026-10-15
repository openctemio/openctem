package entitlement

// Feature denies: which features an organization may not use. Every feature
// is allowed unless the operator or a source denied it; core modules are
// always allowed. A feature that becomes denied keeps read access for
// limits.GracePeriod (reads and export work; writes are refused and its jobs
// stop). The module service reads NotEntitled for every route gate, job and
// console list; a read error is reported, never turned into "allowed"
// (fail-closed).

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Admin audit actions of feature denies.
const (
	ActionFeatureDenySet     = "organization.feature_deny_set"
	ActionFeatureDenyRemoved = "organization.feature_deny_removed"
)

// Module entitlement states.
const (
	StateCore      = "core"
	StateAvailable = "available"
	StateDenied    = "denied"
	StateGrace     = "grace" // denied recently: read-only until ReadOnlyUntil
)

// ModulesChangeNotifier is told when denies change so every cache of the
// module state drops the organization ("" = every organization).
type ModulesChangeNotifier func(tenantID string)

// SetModulesChangeNotifier wires the cache invalidation of the module state.
func (s *Service) SetModulesChangeNotifier(n ModulesChangeNotifier) { s.modulesChanged = n }

// activeDenies returns the organization's active denies by feature: the
// operator's and every source's (the operator's row is reported when both
// deny).
func (s *Service) activeDenies(ctx context.Context, tenantID shared.ID) (map[string]limits.FeatureDeny, error) {
	now := s.now()
	out := map[string]limits.FeatureDeny{}
	for _, src := range s.sources {
		list, err := src.Denies(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, d := range list {
			if d.TenantID == tenantID && d.Active(now) {
				out[d.Feature] = d
			}
		}
	}
	ops, err := s.repo.ListDenies(ctx, tenantID, limits.OriginOperator)
	if err != nil {
		return nil, err
	}
	for _, d := range ops {
		if d.Active(now) {
			out[d.Feature] = d
		}
	}
	return out, nil
}

// DeniedFeatures lists the organization's denied features with their grace.
func (s *Service) DeniedFeatures(ctx context.Context, tenantID shared.ID) ([]DeniedFeature, error) {
	denies, err := s.activeDenies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	grace, err := s.repo.ListGrace(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]DeniedFeature, 0, len(denies))
	for f, d := range denies {
		df := DeniedFeature{Feature: f, Origin: d.Origin}
		if until, ok := grace[f]; ok && now.Before(until) {
			u := until
			df.ReadOnlyUntil = &u
		}
		out = append(out, df)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Feature < out[j].Feature })
	return out, nil
}

// Allowed reports whether the organization may use a named feature (see
// limits.NamedFeatures). A read error returns false with the error: the
// caller refuses (fail-closed).
func (s *Service) Allowed(ctx context.Context, tenantID shared.ID, feature string) (bool, error) {
	if !limits.IsFeature(feature) {
		return false, limits.ErrInvalid
	}
	denies, err := s.activeDenies(ctx, tenantID)
	if err != nil {
		return false, err
	}
	_, denied := denies[feature]
	return !denied, nil
}

// ModuleEntitlement is one module's state for one organization.
type ModuleEntitlement struct {
	Module   string `json:"module"`
	Name     string `json:"name"`
	Core     bool   `json:"core"`
	Entitled bool   `json:"entitled"`
	State    string `json:"state"`
	// Origin, Reason and ExpiresAt describe the deny, when there is one.
	Origin    limits.Origin `json:"origin,omitempty"`
	Reason    string        `json:"reason,omitempty"`
	ExpiresAt *time.Time    `json:"expires_at,omitempty"`
	// ReadOnlyUntil: the organization lost the module and keeps read access
	// (and export) until then; writes are refused and its jobs are stopped.
	ReadOnlyUntil *time.Time `json:"read_only_until,omitempty"`
}

// ModuleEntitlements returns every top-level module of the registry with the
// organization's state.
func (s *Service) ModuleEntitlements(ctx context.Context, tenantID shared.ID) ([]ModuleEntitlement, error) {
	denies, err := s.activeDenies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	grace, err := s.repo.ListGrace(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]ModuleEntitlement, 0, len(moduledom.Registry))
	for _, d := range moduledom.Registry {
		if d.Parent != "" {
			continue // a sub-module follows its parent
		}
		e := ModuleEntitlement{Module: d.ID, Name: d.Name, Core: d.Core, Entitled: true, State: StateAvailable}
		deny, denied := denies[d.ID]
		switch {
		case d.Core:
			e.State = StateCore
		case denied:
			e.Entitled, e.State = false, StateDenied
			e.Origin, e.Reason, e.ExpiresAt = deny.Origin, deny.Reason, deny.ExpiresAt
			if until, ok := grace[d.ID]; ok && now.Before(until) {
				u := until
				e.State, e.ReadOnlyUntil = StateGrace, &u
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// NotEntitled returns the modules the organization may not use: top-level
// modules and their sub-modules. The value is the end of the read-only grace
// (nil: no access at all). An error means the state could not be read; the
// caller treats every non-core module as unavailable.
func (s *Service) NotEntitled(ctx context.Context, tenantID string) (map[string]*time.Time, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, err
	}
	list, err := s.ModuleEntitlements(ctx, id)
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

// deniedSet returns the denied features, or nil when they cannot be read
// (logged).
func (s *Service) deniedSet(ctx context.Context, tenantID shared.ID) map[string]bool {
	denies, err := s.activeDenies(ctx, tenantID)
	if err != nil {
		s.log.Error("read feature denies for grace", "tenant_id", tenantID.String(), "error", err)
		return nil
	}
	set := map[string]bool{}
	for f := range denies {
		set[f] = true
	}
	return set
}

// withGrace runs change and then starts read-only grace for the features it
// newly denied and ends it for those it allowed again. This is the one
// over-limit hook for features: whatever takes a feature away (an operator
// deny, the control plane, a future license expiry) goes through it, and
// nothing is deleted. When the state cannot be read around the change, no
// grace is started: the change stands.
func (s *Service) withGrace(ctx context.Context, tenantID shared.ID, change func() error) error {
	before := s.deniedSet(ctx, tenantID)
	if err := change(); err != nil {
		return err
	}
	after := s.deniedSet(ctx, tenantID)
	if before != nil && after != nil {
		var lost, regained []string
		for f := range after {
			if !before[f] {
				lost = append(lost, f)
			}
		}
		for f := range before {
			if !after[f] {
				regained = append(regained, f)
			}
		}
		if err := s.repo.StartGrace(ctx, tenantID, lost, s.now().UTC().Add(limits.GracePeriod)); err != nil {
			s.log.Error("start feature grace", "tenant_id", tenantID.String(), "error", err)
		}
		if err := s.repo.EndGrace(ctx, tenantID, regained); err != nil {
			s.log.Error("end feature grace", "tenant_id", tenantID.String(), "error", err)
		}
	}
	if s.modulesChanged != nil {
		s.modulesChanged(tenantID.String())
	}
	return nil
}

// DenyInput is one operator deny of a feature.
type DenyInput struct {
	Feature   string
	Reason    string
	ExpiresAt *time.Time
}

// Validate reports limits.ErrInvalid unless the input names a deniable
// feature, a reason and, if any, an expiry after now. Handlers call it
// before asking for a step-up code, so a typo does not spend the code.
func (in DenyInput) Validate(now time.Time) error {
	if !limits.IsFeature(in.Feature) || !ValidReason(in.Reason) || (in.ExpiresAt != nil && !in.ExpiresAt.After(now)) {
		return limits.ErrInvalid
	}
	return nil
}

// PutDeny denies a feature to an organization (operator; audited). The
// HTTP layer requires a step-up code first.
func (s *Service) PutDeny(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, in DenyInput, ip, ua string) error {
	now := s.now().UTC()
	if actor == nil {
		return limits.ErrInvalid
	}
	if err := in.Validate(now); err != nil {
		return err
	}
	reason := strings.TrimSpace(in.Reason)
	id := actor.ID()
	d := limits.FeatureDeny{TenantID: tenantID, Feature: in.Feature, Origin: limits.OriginOperator, Reason: reason,
		ExpiresAt: in.ExpiresAt, SetBy: &id, SetAt: now}
	if err := s.withGrace(ctx, tenantID, func() error { return s.repo.SetDeny(ctx, d) }); err != nil {
		return err
	}
	body := map[string]any{"feature": in.Feature, "reason": reason}
	if in.ExpiresAt != nil {
		body["expires_at"] = in.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.writeAudit(ctx, actor, ActionFeatureDenySet, &tenantID, "tenant", body, ip, ua)
	return nil
}

// DeleteDeny lifts the operator's deny of a feature (audited with the
// reason). The HTTP layer requires a step-up code first.
func (s *Service) DeleteDeny(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, feature, reason, ip, ua string) error {
	if actor == nil || !limits.IsFeature(feature) || !ValidReason(reason) {
		return limits.ErrInvalid
	}
	if err := s.withGrace(ctx, tenantID, func() error {
		return s.repo.DeleteDeny(ctx, tenantID, feature, limits.OriginOperator)
	}); err != nil {
		return err
	}
	s.writeAudit(ctx, actor, ActionFeatureDenyRemoved, &tenantID, "tenant",
		map[string]any{"feature": feature, "reason": strings.TrimSpace(reason)}, ip, ua)
	return nil
}

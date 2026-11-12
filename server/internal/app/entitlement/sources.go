package entitlement

import (
	"context"
	"errors"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/admin"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ControlPlaneSource supplies the limits and denies a hosted service's
// control plane wrote through the internal API (rows of origin
// control_plane). It is configured only when the internal API is on; a
// self-hosted install runs with no source.
type ControlPlaneSource struct {
	repo limits.Repository
}

// NewControlPlaneSource creates the source.
func NewControlPlaneSource(repo limits.Repository) *ControlPlaneSource {
	return &ControlPlaneSource{repo: repo}
}

// Name implements limits.Source.
func (c *ControlPlaneSource) Name() string { return string(limits.OriginControlPlane) }

// Limits implements limits.Source.
func (c *ControlPlaneSource) Limits(ctx context.Context, tenantID shared.ID) ([]limits.Limit, error) {
	return c.repo.ListLimits(ctx, tenantID, limits.OriginControlPlane)
}

// Denies implements limits.Source.
func (c *ControlPlaneSource) Denies(ctx context.Context, tenantID shared.ID) ([]limits.FeatureDeny, error) {
	return c.repo.ListDenies(ctx, tenantID, limits.OriginControlPlane)
}

// ControlPlaneCall identifies one call of the control plane, for the audit.
type ControlPlaneCall struct {
	// Subject is the calling service (the token's sub).
	Subject string
	// TokenID is the token's jti.
	TokenID string
	IP      string
	Reason  string
}

// ApplyControlPlane replaces every limit and deny the control plane set for
// the organization (one transaction) and audits it as the control-plane
// actor. Features it newly denies start the read-only grace; nothing is
// deleted. A key absent from lims is no longer limited by the control plane
// (the operator's own limits are untouched).
func (s *Service) ApplyControlPlane(ctx context.Context, tenantID shared.ID, lims limits.Limits, denied []string, call ControlPlaneCall) error {
	if !ValidReason(call.Reason) {
		return limits.ErrInvalid
	}
	now := s.now().UTC()
	reason := strings.TrimSpace(call.Reason)
	rows := make([]limits.Limit, 0, len(lims))
	for k, v := range lims {
		if !k.PerOrganization() || v < 0 {
			return limits.ErrInvalid
		}
		rows = append(rows, limits.Limit{TenantID: tenantID, Key: k, Value: v, Origin: limits.OriginControlPlane, Reason: reason, SetAt: now})
	}
	seen := map[string]bool{}
	denies := make([]limits.FeatureDeny, 0, len(denied))
	for _, f := range denied {
		if !limits.IsFeature(f) {
			return limits.ErrInvalid
		}
		if seen[f] {
			continue
		}
		seen[f] = true
		denies = append(denies, limits.FeatureDeny{TenantID: tenantID, Feature: f, Origin: limits.OriginControlPlane, Reason: reason, SetAt: now})
	}
	if err := s.withGrace(ctx, tenantID, func() error {
		return s.repo.ReplaceOrigin(ctx, tenantID, limits.OriginControlPlane, rows, denies)
	}); err != nil {
		return err
	}
	body := map[string]any{"reason": reason, "denied_features": denied, "subject": call.Subject, "token_id": call.TokenID}
	for k, v := range lims {
		body["limit."+string(k)] = v
	}
	entry := admin.NewAuditLogBuilder(nil, ActionControlPlaneApplied).
		Resource("tenant", &tenantID, "").
		Context(call.IP, "").
		Request("PUT", "", body).
		High().
		Build()
	entry.AdminEmail = ControlPlaneActor
	s.createAudit(ctx, ActionControlPlaneApplied, entry)
	return nil
}

// Usage counts what the organization uses (aggregate counts only); findings
// only when asked, the count being costly.
func (s *Service) Usage(ctx context.Context, tenantID shared.ID, withFindings bool) (map[limits.Key]int, error) {
	return s.repo.Usage(ctx, tenantID, withFindings)
}

// ApplySelfServiceDefaultsFromControlPlane replaces the self-service default
// limits (the limits every organization a person creates starts with, and
// the per-person cap), as the control plane. Audited critical as the
// control-plane actor.
func (s *Service) ApplySelfServiceDefaultsFromControlPlane(ctx context.Context, d limits.Limits, call ControlPlaneCall) error {
	if !ValidReason(call.Reason) {
		return limits.ErrInvalid
	}
	if err := d.Validate(); err != nil {
		return err
	}
	_, version, err := s.repo.GetSelfServiceDefaults(ctx)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return err
	}
	v, err := s.repo.SaveSelfServiceDefaults(ctx, d, version, nil, s.now().UTC())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cached, s.version, s.cachedAt = d, v, s.now()
	s.mu.Unlock()
	body := map[string]any{"version": v, "reason": strings.TrimSpace(call.Reason), "subject": call.Subject, "token_id": call.TokenID}
	for k, val := range d {
		body["limit."+string(k)] = val
	}
	entry := admin.NewAuditLogBuilder(nil, ActionSelfServiceDefaultsChanged).
		Resource("self_service_default_limits", nil, "").
		Context(call.IP, "").
		Request("PUT", "", body).
		Critical().
		Build()
	entry.AdminEmail = ControlPlaneActor
	s.createAudit(ctx, ActionSelfServiceDefaultsChanged, entry)
	return nil
}

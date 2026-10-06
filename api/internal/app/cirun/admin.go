package cirun

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ---------------------------------------------------------- trust configs --

// TrustConfigInput creates or changes a trust configuration.
type TrustConfigInput struct {
	Name          string
	Provider      string
	Issuer        string
	Audience      string
	DefaultBranch string
	Rules         cirun.Rules
	Enabled       *bool
}

// ListTrustConfigs returns the tenant's trust configurations.
func (s *Service) ListTrustConfigs(ctx context.Context, tenantID shared.ID) ([]cirun.TrustConfig, error) {
	return s.repo.ListTrustConfigs(ctx, tenantID)
}

// GetTrustConfig returns one trust configuration of the tenant.
func (s *Service) GetTrustConfig(ctx context.Context, tenantID, id shared.ID) (*cirun.TrustConfig, error) {
	return s.repo.GetTrustConfig(ctx, tenantID, id)
}

// CreateTrustConfig adds a trust configuration (audited).
func (s *Service) CreateTrustConfig(ctx context.Context, tenantID shared.ID, in TrustConfigInput, a Actor) (*cirun.TrustConfig, error) {
	now := s.now().UTC()
	c := &cirun.TrustConfig{ID: shared.NewID(), TenantID: tenantID, Name: in.Name, Provider: cirun.Provider(in.Provider),
		Issuer: in.Issuer, Audience: in.Audience, DefaultBranch: in.DefaultBranch, Rules: in.Rules, Enabled: true,
		CreatedAt: now, UpdatedAt: now}
	if in.Enabled != nil {
		c.Enabled = *in.Enabled
	}
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		c.CreatedBy = &uid
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := s.repo.CreateTrustConfig(ctx, c); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCITrustConfigCreated, auditdom.ResourceTypeCITrustConfig, c.ID.String()).
		WithResourceName(c.Name).
		WithMessage(fmt.Sprintf("CI trust configuration %q created for %s", c.Name, c.Issuer)).
		WithChanges(auditdom.NewChanges().SetAfter("config", trustSnapshot(c))))
	return c, nil
}

// UpdateTrustConfig changes a trust configuration (audited). The provider
// cannot change.
func (s *Service) UpdateTrustConfig(ctx context.Context, tenantID, id shared.ID, in TrustConfigInput, a Actor) (*cirun.TrustConfig, error) {
	cur, err := s.repo.GetTrustConfig(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	before := trustSnapshot(cur)
	next := *cur
	if in.Provider != "" && cirun.Provider(in.Provider) != cur.Provider {
		return nil, fmt.Errorf("%w: the provider of a trust configuration cannot change", shared.ErrValidation)
	}
	next.Name, next.Issuer, next.Audience, next.DefaultBranch, next.Rules = in.Name, in.Issuer, in.Audience, in.DefaultBranch, in.Rules
	if in.Enabled != nil {
		next.Enabled = *in.Enabled
	}
	next.Normalize()
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := s.repo.UpdateTrustConfig(ctx, &next); err != nil {
		return nil, err
	}
	// Disabling a configuration, or pointing it at another issuer or
	// audience, withdraws the trust its pipelines were admitted under.
	if (cur.Enabled && !next.Enabled) || cur.Issuer != next.Issuer || cur.Audience != next.Audience {
		if err := s.revokePipelines(ctx, tenantID, &next, a, "the trust configuration was disabled or re-pointed"); err != nil {
			return nil, err
		}
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCITrustConfigUpdated, auditdom.ResourceTypeCITrustConfig, id.String()).
		WithResourceName(next.Name).
		WithMessage(fmt.Sprintf("CI trust configuration %q changed", next.Name)).
		WithChanges(auditdom.NewChanges().Set("config", before, trustSnapshot(&next))))
	return &next, nil
}

// DeleteTrustConfig removes a trust configuration (audited). Runs it
// admitted stay as history; its pipelines are revoked and the upload tokens
// of its runs still running stop working at once.
func (s *Service) DeleteTrustConfig(ctx context.Context, tenantID, id shared.ID, a Actor) error {
	cur, err := s.repo.GetTrustConfig(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.revokePipelines(ctx, tenantID, cur, a, "the trust configuration was deleted"); err != nil {
		return err
	}
	if err := s.repo.DeleteTrustConfig(ctx, tenantID, id); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCITrustConfigDeleted, auditdom.ResourceTypeCITrustConfig, id.String()).
		WithResourceName(cur.Name).
		WithMessage(fmt.Sprintf("CI trust configuration %q deleted", cur.Name)).
		WithChanges(auditdom.NewChanges().SetBefore("config", trustSnapshot(cur))))
	return nil
}

// revokePipelines revokes the configuration's pipelines and its running
// runs' upload tokens (audited when any pipeline was revoked).
func (s *Service) revokePipelines(ctx context.Context, tenantID shared.ID, c *cirun.TrustConfig, a Actor, why string) error {
	n, err := s.repo.RevokeTrustConfigPipelines(ctx, tenantID, c.ID, s.now().UTC())
	if err != nil {
		return fmt.Errorf("revoke pipelines: %w", err)
	}
	if n > 0 {
		s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIPipelinesRevoked, auditdom.ResourceTypeCITrustConfig, c.ID.String()).
			WithResourceName(c.Name).
			WithMessage(fmt.Sprintf("%d CI pipeline(s) of %q revoked: %s", n, c.Name, why)).
			WithMetadata("pipelines", n))
	}
	return nil
}

func trustSnapshot(c *cirun.TrustConfig) map[string]any {
	return map[string]any{"name": c.Name, "provider": string(c.Provider), "issuer": c.Issuer, "audience": c.Audience,
		"default_branch": c.DefaultBranch, "enabled": c.Enabled, "rules": c.Rules}
}

// -------------------------------------------------------------------- runs --

// ListRuns returns the tenant's runs, within the caller's data scope.
func (s *Service) ListRuns(ctx context.Context, tenantID shared.ID, f cirun.RunFilter) ([]cirun.Run, int, error) {
	return s.repo.ListRuns(ctx, tenantID, f)
}

// GetRun returns one run of the tenant.
func (s *Service) GetRun(ctx context.Context, tenantID, id shared.ID) (*cirun.Run, error) {
	return s.repo.GetRun(ctx, tenantID, id)
}

// ----------------------------------------------------------------- policies --

// GatePolicyInput creates or changes a gate policy.
type GatePolicyInput struct {
	ScopeType       string
	ScopeID         *shared.ID
	Enabled         *bool
	Mode            string
	FailOnSeverity  string
	NewFindingsOnly *bool
	FailOnKEV       *bool
	EPSSThreshold   *float64
}

// ListGatePolicies returns the tenant's gate policies.
func (s *Service) ListGatePolicies(ctx context.Context, tenantID shared.ID) ([]cirun.GatePolicy, error) {
	return s.repo.ListGatePolicies(ctx, tenantID)
}

// CreateGatePolicy adds a policy for a scope of the tenant (audited).
func (s *Service) CreateGatePolicy(ctx context.Context, tenantID shared.ID, in GatePolicyInput, a Actor) (*cirun.GatePolicy, error) {
	def := cirun.DefaultGatePolicy()
	now := s.now().UTC()
	p := &cirun.GatePolicy{ID: shared.NewID(), TenantID: tenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID,
		Enabled: true, Mode: def.Mode, FailOnSeverity: def.FailOnSeverity, NewFindingsOnly: def.NewFindingsOnly,
		FailOnKEV: def.FailOnKEV, CreatedAt: now, UpdatedAt: now}
	applyPolicyInput(p, in)
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		p.CreatedBy, p.UpdatedBy = &uid, &uid
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := s.checkPolicyScope(ctx, tenantID, p); err != nil {
		return nil, err
	}
	if err := s.repo.CreateGatePolicy(ctx, p); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGatePolicyCreated, auditdom.ResourceTypeCIGatePolicy, p.ID.String()).
		WithResourceName(policyName(p)).
		WithMessage("CI gate policy created for "+policyName(p)).
		WithChanges(auditdom.NewChanges().SetAfter("config", policySnapshot(p))))
	return p, nil
}

// UpdateGatePolicy changes a policy (audited). The scope cannot change.
func (s *Service) UpdateGatePolicy(ctx context.Context, tenantID, id shared.ID, in GatePolicyInput, a Actor) (*cirun.GatePolicy, error) {
	cur, err := s.repo.GetGatePolicy(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	before := policySnapshot(cur)
	next := *cur
	in.ScopeType, in.ScopeID = "", nil
	applyPolicyInput(&next, in)
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		next.UpdatedBy = &uid
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := s.repo.UpdateGatePolicy(ctx, &next); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGatePolicyUpdated, auditdom.ResourceTypeCIGatePolicy, id.String()).
		WithResourceName(policyName(&next)).
		WithMessage("CI gate policy changed for "+policyName(&next)).
		WithChanges(auditdom.NewChanges().Set("config", before, policySnapshot(&next))))
	return &next, nil
}

// DeleteGatePolicy removes a policy (audited).
func (s *Service) DeleteGatePolicy(ctx context.Context, tenantID, id shared.ID, a Actor) error {
	cur, err := s.repo.GetGatePolicy(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.DeleteGatePolicy(ctx, tenantID, id); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGatePolicyDeleted, auditdom.ResourceTypeCIGatePolicy, id.String()).
		WithResourceName(policyName(cur)).
		WithMessage("CI gate policy deleted for "+policyName(cur)).
		WithChanges(auditdom.NewChanges().SetBefore("config", policySnapshot(cur))))
	return nil
}

func applyPolicyInput(p *cirun.GatePolicy, in GatePolicyInput) {
	if in.ScopeType != "" {
		p.ScopeType = in.ScopeType
	}
	if in.ScopeID != nil {
		p.ScopeID = in.ScopeID
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if in.Mode != "" {
		p.Mode = in.Mode
	}
	if in.FailOnSeverity != "" {
		p.FailOnSeverity = in.FailOnSeverity
	}
	if in.NewFindingsOnly != nil {
		p.NewFindingsOnly = *in.NewFindingsOnly
	}
	if in.FailOnKEV != nil {
		p.FailOnKEV = *in.FailOnKEV
	}
	p.EPSSThreshold = in.EPSSThreshold
}

// checkPolicyScope makes sure a policy's repository or business unit is the
// tenant's: another tenant's id answers "not found".
func (s *Service) checkPolicyScope(ctx context.Context, tenantID shared.ID, p *cirun.GatePolicy) error {
	switch p.ScopeType {
	case cirun.ScopeRepository:
		a, err := s.assets.GetByID(ctx, tenantID, *p.ScopeID)
		if err != nil {
			return err
		}
		if a.Type() != asset.AssetTypeRepository {
			return fmt.Errorf("%w: a repository policy needs a repository asset", shared.ErrValidation)
		}
	case cirun.ScopeBusinessUnit:
		if s.units == nil {
			return fmt.Errorf("%w: business units are not available", shared.ErrValidation)
		}
		ok, err := s.units.BusinessUnitExists(ctx, tenantID, *p.ScopeID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: business unit not found", shared.ErrNotFound)
		}
	}
	return nil
}

func policyName(p *cirun.GatePolicy) string {
	if p.ScopeID == nil {
		return p.ScopeType
	}
	return p.ScopeType + " " + p.ScopeID.String()
}

func policySnapshot(p *cirun.GatePolicy) map[string]any {
	return map[string]any{"scope_type": p.ScopeType, "enabled": p.Enabled, "mode": p.Mode,
		"fail_on_severity": p.FailOnSeverity, "new_findings_only": p.NewFindingsOnly, "fail_on_kev": p.FailOnKEV,
		"epss_threshold": p.EPSSThreshold}
}

// ---------------------------------------------------------------- overrides --

// OverrideInput is a break-glass request.
type OverrideInput struct {
	RepositoryAssetID shared.ID
	CommitSHA         string
	Reason            string
	// Duration defaults to DefaultOverrideTTL, at most MaxOverrideTTL.
	Duration time.Duration
}

// CreateOverride lets one commit pass the gate for a while (audited, high
// severity). The caller has checked the asset is in their data scope.
func (s *Service) CreateOverride(ctx context.Context, tenantID shared.ID, in OverrideInput, a Actor) (*cirun.GateOverride, error) {
	repo, err := s.assets.GetByID(ctx, tenantID, in.RepositoryAssetID)
	if err != nil {
		return nil, err
	}
	if repo.Type() != asset.AssetTypeRepository {
		return nil, fmt.Errorf("%w: break-glass applies to a repository", shared.ErrValidation)
	}
	d := in.Duration
	if d == 0 {
		d = cirun.DefaultOverrideTTL
	}
	now := s.now().UTC()
	o := &cirun.GateOverride{ID: shared.NewID(), TenantID: tenantID, RepositoryAssetID: repo.ID(), CommitSHA: in.CommitSHA,
		Reason: in.Reason, CreatedByEmail: a.Email, ExpiresAt: now.Add(d), CreatedAt: now}
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		o.CreatedBy = &uid
	}
	if err := o.Validate(now); err != nil {
		return nil, err
	}
	if err := s.repo.CreateOverride(ctx, o); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGateOverrideCreated, auditdom.ResourceTypeCIGateOverride, o.ID.String()).
		WithResourceName(repo.Name()).
		WithMessage(fmt.Sprintf("Break-glass for %s at %s until %s: %s", repo.Name(), o.CommitSHA, o.ExpiresAt.Format(time.RFC3339), o.Reason)).
		WithMetadata("repository_asset_id", repo.ID().String()).
		WithMetadata("commit_sha", o.CommitSHA).
		WithMetadata("expires_at", o.ExpiresAt.Format(time.RFC3339)).
		WithMetadata("reason", o.Reason))
	oid := o.ID
	s.alertAdmins(ctx, tenantID, breakGlassAlert(AdminAlert{
		Title: "CI break-glass created: " + repo.Name(),
		Body: fmt.Sprintf("%s let commit %s of %s pass the CI gate until %s. Reason: %s",
			nonEmpty(a.Email, "an administrator"), shortSHA(o.CommitSHA), repo.Name(), o.ExpiresAt.Format(time.RFC3339), o.Reason),
		URL: "/settings/scanning/ci", Aggregate: "ci_gate_override", AggregateID: &oid,
		Metadata: map[string]any{"action": "created", "repository": repo.Name(), "commit_sha": o.CommitSHA,
			"expires_at": o.ExpiresAt.Format(time.RFC3339)},
	}))
	return o, nil
}

// ListOverrides returns the tenant's overrides within a data scope.
func (s *Service) ListOverrides(ctx context.Context, tenantID shared.ID, assetID *shared.ID, scope *shared.DataScope) ([]cirun.GateOverride, error) {
	return s.repo.ListOverrides(ctx, tenantID, assetID, scope)
}

// GetOverride returns one override of the tenant.
func (s *Service) GetOverride(ctx context.Context, tenantID, id shared.ID) (*cirun.GateOverride, error) {
	return s.repo.GetOverride(ctx, tenantID, id)
}

// RevokeOverride ends an override now (audited).
func (s *Service) RevokeOverride(ctx context.Context, tenantID, id shared.ID, a Actor) error {
	o, err := s.repo.GetOverride(ctx, tenantID, id)
	if err != nil {
		return err
	}
	by, err := shared.IDFromString(a.UserID)
	if err != nil {
		by = shared.ID{}
	}
	if err := s.repo.RevokeOverride(ctx, tenantID, id, by, s.now().UTC()); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return fmt.Errorf("%w: the override is already revoked", shared.ErrConflict)
		}
		return err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGateOverrideRevoked, auditdom.ResourceTypeCIGateOverride, id.String()).
		WithMessage("Break-glass revoked for commit "+o.CommitSHA).
		WithMetadata("repository_asset_id", o.RepositoryAssetID.String()).
		WithMetadata("commit_sha", o.CommitSHA))
	return nil
}

package cirun

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
// OwnerPins lists the organization or namespace ids a configuration pinned.
func (s *Service) OwnerPins(ctx context.Context, tenantID, id shared.ID) ([]cirun.OwnerPin, error) {
	return s.repo.OwnerPins(ctx, tenantID, id)
}

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
	// Changing which organizations or repositories a configuration trusts, or
	// its issuer, drops its owner pins: they are taken again at the next
	// admitted exchange.
	if cur.Issuer != next.Issuer || !slices.Equal(cur.Rules.Owners, next.Rules.Owners) ||
		!slices.Equal(cur.Rules.Repositories, next.Rules.Repositories) {
		if _, err := s.repo.ResetOwnerPins(ctx, tenantID, id); err != nil {
			return nil, fmt.Errorf("reset owner pins: %w", err)
		}
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
	// Modes, when set, replaces the policy's modes.
	Modes *cirun.PolicyModes
	// AllowRepoPolicy, when set, allows or forbids repository files.
	AllowRepoPolicy *bool
	// FixableOnly, when set: vulnerabilities without a fixed version do not
	// block on severity or EPSS.
	FixableOnly *bool
	// BaselineOnFirstRun and BaselineSecretsBlock, when set, change the gate
	// baseline settings; BaselineGraceDays is replaced (nil: no end).
	BaselineOnFirstRun   *bool
	BaselineSecretsBlock *bool
	BaselineGraceDays    *int
	// Fields, when set, replaces the fields the policy sets (the others are
	// inherited). Nil on create: every field.
	Fields *[]string
	// LockedFields, when set, replaces the fields no layer below may loosen
	// (organization and business unit policies).
	LockedFields *[]string
	// Reason and ExpiresAt are replaced on every write (repository
	// policies); a change that loosens a repository or business unit policy
	// needs a reason.
	Reason    string
	ExpiresAt *time.Time
}

// ErrStepUpUnavailable: a change that loosens the gate needs step-up, and
// none is wired (fail closed).
var ErrStepUpUnavailable = errors.New("step-up re-authentication is not available")

// SetStepUpGate sets the re-authentication a change that loosens the gate
// needs.
func (s *Service) SetStepUpGate(g shared.RecentAuthGate) { s.stepUp = g }

// GetGatePolicy returns one policy of the tenant.
func (s *Service) GetGatePolicy(ctx context.Context, tenantID, id shared.ID) (*cirun.GatePolicy, error) {
	return s.repo.GetGatePolicy(ctx, tenantID, id)
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
		FailOnKEV: def.FailOnKEV, AllowRepoPolicy: true, BaselineOnFirstRun: true, BaselineSecretsBlock: true, Fields: slices.Clone(cirun.PolicyFields), CreatedAt: now, UpdatedAt: now}
	applyPolicyInput(p, in)
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		p.CreatedBy, p.UpdatedBy = &uid, &uid
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := p.ValidateLayer(now); err != nil {
		return nil, err
	}
	if err := s.checkPolicyScope(ctx, tenantID, p); err != nil {
		return nil, err
	}
	inh, err := s.inheritedPolicy(ctx, tenantID, p)
	if err != nil {
		return nil, err
	}
	if err := refuseLockedLoosening(inh, *p); err != nil {
		return nil, err
	}
	loosened := cirun.Loosens(inh.policy, inh.apply(*p, now))
	if err := s.requireToLoosen(ctx, a, p, loosened); err != nil {
		return nil, err
	}
	if err := s.repo.CreateGatePolicy(ctx, p); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGatePolicyCreated, auditdom.ResourceTypeCIGatePolicy, p.ID.String()).
		WithResourceName(policyName(p)).
		WithMessage("CI gate policy created for "+policyName(p)).
		WithChanges(auditdom.NewChanges().SetAfter("config", policySnapshot(p))))
	s.announceLoosened(ctx, tenantID, a, p, loosened)
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
	now := s.now().UTC()
	if err := next.ValidateLayer(now); err != nil {
		return nil, err
	}
	inh, err := s.inheritedPolicy(ctx, tenantID, cur)
	if err != nil {
		return nil, err
	}
	if err := refuseLockedLoosening(inh, next); err != nil {
		return nil, err
	}
	loosened := cirun.Loosens(inh.apply(*cur, now), inh.apply(next, now))
	loosened = append(loosened, layerLoosens(inh, *cur, &next, now)...)
	if err := s.requireToLoosen(ctx, a, &next, loosened); err != nil {
		return nil, err
	}
	if err := s.repo.UpdateGatePolicy(ctx, &next); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGatePolicyUpdated, auditdom.ResourceTypeCIGatePolicy, id.String()).
		WithResourceName(policyName(&next)).
		WithMessage("CI gate policy changed for "+policyName(&next)).
		WithChanges(auditdom.NewChanges().Set("config", before, policySnapshot(&next))))
	s.announceLoosened(ctx, tenantID, a, &next, loosened)
	return &next, nil
}

// DeleteGatePolicy removes a policy (audited).
func (s *Service) DeleteGatePolicy(ctx context.Context, tenantID, id shared.ID, a Actor) error {
	cur, err := s.repo.GetGatePolicy(ctx, tenantID, id)
	if err != nil {
		return err
	}
	inh, err := s.inheritedPolicy(ctx, tenantID, cur)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	loosened := cirun.Loosens(inh.apply(*cur, now), inh.policy)
	loosened = append(loosened, layerLoosens(inh, *cur, nil, now)...)
	if err := s.requireStepUpToLoosen(ctx, a, loosened); err != nil {
		return err
	}
	if err := s.repo.DeleteGatePolicy(ctx, tenantID, id); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGatePolicyDeleted, auditdom.ResourceTypeCIGatePolicy, id.String()).
		WithResourceName(policyName(cur)).
		WithMessage("CI gate policy deleted for "+policyName(cur)).
		WithChanges(auditdom.NewChanges().SetBefore("config", policySnapshot(cur))))
	s.announceLoosened(ctx, tenantID, a, cur, loosened)
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
	if in.Modes != nil {
		p.Modes = *in.Modes
	}
	if in.AllowRepoPolicy != nil {
		p.AllowRepoPolicy = *in.AllowRepoPolicy
	}
	if in.FixableOnly != nil {
		p.FixableOnly = *in.FixableOnly
	}
	if in.BaselineOnFirstRun != nil {
		p.BaselineOnFirstRun = *in.BaselineOnFirstRun
	}
	if in.BaselineSecretsBlock != nil {
		p.BaselineSecretsBlock = *in.BaselineSecretsBlock
	}
	p.BaselineGraceDays = in.BaselineGraceDays
	if in.Fields != nil {
		p.Fields = slices.Clone(*in.Fields)
	}
	if in.LockedFields != nil {
		p.LockedFields = slices.Clone(*in.LockedFields)
	}
	p.Reason = in.Reason
	p.ExpiresAt = in.ExpiresAt
}

// inherited is what applies to a policy's scope without the policy, and the
// fields a layer above locks.
type inherited struct {
	policy cirun.GatePolicy
	locked map[string]bool
}

// apply is what applies to the scope with p on top (p's fields while it is
// active; a looser value of a locked field keeps the inherited one).
func (i inherited) apply(p cirun.GatePolicy, now time.Time) cirun.GatePolicy {
	return cirun.ApplyLayer(i.policy, i.locked, p, now)
}

// inheritedPolicy is what applies to p's scope without p: for a repository,
// the organization's fields and per field the strictest of its business
// units', over the default; for a business unit, the organization's; for
// the organization, the default.
func (s *Service) inheritedPolicy(ctx context.Context, tenantID shared.ID, p *cirun.GatePolicy) (inherited, error) {
	var ps []cirun.GatePolicy
	var err error
	switch p.ScopeType {
	case cirun.ScopeRepository:
		ps, err = s.repo.GatePoliciesFor(ctx, tenantID, *p.ScopeID)
	case cirun.ScopeBusinessUnit:
		ps, err = s.repo.ListGatePolicies(ctx, tenantID)
	default:
		return inherited{policy: cirun.DefaultGatePolicy(), locked: map[string]bool{}}, nil
	}
	if err != nil {
		return inherited{}, fmt.Errorf("load gate policies: %w", err)
	}
	keep := make([]cirun.GatePolicy, 0, len(ps))
	for _, q := range ps {
		if q.ID == p.ID || q.ScopeType == cirun.ScopeRepository ||
			(p.ScopeType == cirun.ScopeBusinessUnit && q.ScopeType != cirun.ScopeTenant) {
			continue
		}
		keep = append(keep, q)
	}
	res := cirun.Resolve(keep, s.now().UTC())
	out := inherited{policy: res.Policy, locked: map[string]bool{}}
	for _, f := range res.Fields {
		if f.LockedBy != "" {
			out.locked[f.Field] = true
		}
	}
	return out, nil
}

// refuseLockedLoosening refuses a policy that sets a looser value for a
// field a layer above locks, whoever asks.
func refuseLockedLoosening(inh inherited, p cirun.GatePolicy) error {
	if fs := cirun.LockedLoosens(inh.policy, inh.locked, p); len(fs) > 0 {
		return fmt.Errorf("%w: %s is locked above this scope and can only be made stricter", cirun.ErrFieldLocked,
			strings.Join(fs, ", "))
	}
	return nil
}

// layerLoosens lists what a change of the layering values loosens: locks
// removed (or the policy carrying them deleted or disabled), and the end of
// a looser repository policy removed or pushed later. next nil: deleted.
func layerLoosens(inh inherited, cur cirun.GatePolicy, next *cirun.GatePolicy, now time.Time) []string {
	var out []string
	if cur.Enabled && len(cur.LockedFields) > 0 {
		if next == nil || !next.Enabled {
			out = append(out, "locked_fields")
		} else {
			for _, f := range cur.LockedFields {
				if !next.Locks(f) {
					out = append(out, "locked_fields")
					break
				}
			}
		}
	}
	if next != nil && cur.ExpiresAt != nil && (next.ExpiresAt == nil || next.ExpiresAt.After(*cur.ExpiresAt)) {
		open := *next
		open.ExpiresAt = nil
		if len(cirun.Loosens(inh.policy, inh.apply(open, now))) > 0 {
			out = append(out, "expires_at")
		}
	}
	return out
}

// requireToLoosen asks, for a change that weakens the gate, a reason (on a
// business unit or repository policy) and a recent sign-in.
func (s *Service) requireToLoosen(ctx context.Context, a Actor, p *cirun.GatePolicy, loosened []string) error {
	if len(loosened) > 0 && p.ScopeType != cirun.ScopeTenant && len([]rune(p.Reason)) < cirun.MinPolicyReason {
		return fmt.Errorf("%w: a change that loosens the gate (%s) needs a reason of at least %d characters",
			shared.ErrValidation, strings.Join(loosened, ", "), cirun.MinPolicyReason)
	}
	return s.requireStepUpToLoosen(ctx, a, loosened)
}

// requireStepUpToLoosen asks for a recent sign-in when a change weakens
// the gate, like a break-glass does.
func (s *Service) requireStepUpToLoosen(ctx context.Context, a Actor, loosened []string) error {
	if len(loosened) == 0 {
		return nil
	}
	if s.stepUp == nil {
		return ErrStepUpUnavailable
	}
	return s.stepUp.RequireRecentAuth(ctx, a.UserID)
}

// announceLoosened records a change that weakened the gate at high severity
// and tells every administrator, on the break-glass channel: it lets
// findings pass that failed before, for every commit of the scope.
func (s *Service) announceLoosened(ctx context.Context, tenantID shared.ID, a Actor, p *cirun.GatePolicy, loosened []string) {
	if len(loosened) == 0 {
		return
	}
	what := strings.Join(loosened, ", ")
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGatePolicyLoosened, auditdom.ResourceTypeCIGatePolicy, p.ID.String()).
		WithResourceName(policyName(p)).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage("CI gate policy for "+policyName(p)+" loosened: "+what).
		WithMetadata("loosened", what))
	pid := p.ID
	s.alertAdmins(ctx, tenantID, breakGlassAlert(AdminAlert{
		Title: "CI gate policy loosened: " + policyName(p),
		Body: fmt.Sprintf("%s changed the CI gate policy for %s so that more findings pass (%s).",
			nonEmpty(a.Email, "an administrator"), policyName(p), what),
		URL: "/ci-cd?tab=setup", Aggregate: "ci_gate_policy", AggregateID: &pid,
		Metadata: map[string]any{"action": "policy_loosened", "scope": policyName(p), "loosened": loosened},
	}))
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
		"epss_threshold": p.EPSSThreshold, "modes": p.Modes, "allow_repo_policy": p.AllowRepoPolicy,
		"fixable_only": p.FixableOnly, "fields": p.Fields, "locked_fields": p.LockedFields, "reason": p.Reason,
		"expires_at": p.ExpiresAt, "baseline_on_first_run": p.BaselineOnFirstRun,
		"baseline_grace_days": p.BaselineGraceDays, "baseline_secrets_block": p.BaselineSecretsBlock}
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
		Reason: in.Reason, ExpiresAt: now.Add(d), CreatedAt: now}
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
		URL: "/ci-cd?tab=setup", Aggregate: "ci_gate_override", AggregateID: &oid,
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

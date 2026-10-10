package scanwindow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records audit events (*auditapp.AuditService).
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// ReferenceChecker refuses selector ids that are not the tenant's own
// (postgres.ScanWindowPolicyRepository).
type ReferenceChecker interface {
	CheckReferences(ctx context.Context, tenantID shared.ID, sel swdom.Selector) error
}

// AssetPreview lists the assets a selector selects and names assets
// (postgres.ScanWindowAssetRepository).
type AssetPreview interface {
	MatchingAssets(ctx context.Context, tenantID shared.ID, sel swdom.Selector, limit int) (int, []swdom.TargetAsset, error)
	AssetNames(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error)
}

// DataScope limits what the caller may see of the assets (*datascope.Enforcer).
type DataScope interface {
	FullDataCaller(ctx context.Context, tenantID shared.ID) (bool, error)
	FilterForCaller(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (func(shared.ID) bool, error)
}

// TOTPVerifier checks a fresh authenticator code of a user
// (*auth.AuthService.VerifyFreshTOTP, adapted to ErrOverrideNeedsTOTP /
// ErrOverrideBadCode).
type TOTPVerifier interface {
	VerifyFreshTOTP(ctx context.Context, userID, code string) error
}

// AdminDirectory lists the tenant's active owners and administrators.
type AdminDirectory interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// InAppNotifier delivers an in-app notification.
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// ChannelEnqueuer puts an event on the organization's notification channels.
type ChannelEnqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// HoldReleaser makes the tenant's deferred jobs due now, so the next claim
// evaluates them under the changed policies (the command repository).
type HoldReleaser interface {
	ReleaseWindowHolds(ctx context.Context, tenantID shared.ID) (int64, error)
}

// Service manages a tenant's scan window policies and overrides and answers
// what the windows mean for targets.
type Service struct {
	repo      swdom.Repository
	refs      ReferenceChecker
	overrides swdom.OverrideRepository
	resolver  *Resolver
	assets    AssetPreview
	scope     DataScope
	audit     AuditLogger
	totp      TOTPVerifier
	admins    AdminDirectory
	inApp     InAppNotifier
	channels  ChannelEnqueuer
	holds     HoldReleaser
	logger    *logger.Logger
	now       func() time.Time
}

// NewService creates the service. The optional parts are wired with Set*.
func NewService(repo swdom.Repository, refs ReferenceChecker, overrides swdom.OverrideRepository, resolver *Resolver, log *logger.Logger) *Service {
	return &Service{repo: repo, refs: refs, overrides: overrides, resolver: resolver,
		logger: log.With("service", "scan_window"), now: time.Now}
}

// SetAssets wires the asset preview and the caller's data scope.
func (s *Service) SetAssets(a AssetPreview, scope DataScope) { s.assets, s.scope = a, scope }

// SetAudit wires the audit log.
func (s *Service) SetAudit(a AuditLogger) { s.audit = a }

// SetTOTP wires the second factor of overrides (none: overrides are
// refused).
func (s *Service) SetTOTP(totp TOTPVerifier) { s.totp = totp }

// SetNotifications wires who hears about overrides.
func (s *Service) SetNotifications(admins AdminDirectory, inApp InAppNotifier, channels ChannelEnqueuer) {
	s.admins, s.inApp, s.channels = admins, inApp, channels
}

// SetHoldReleaser wires the release of deferred jobs on changes.
func (s *Service) SetHoldReleaser(h HoldReleaser) { s.holds = h }

// PolicyView is a policy with what its own windows mean now.
type PolicyView struct {
	*swdom.Policy
	// OpenNow: an allow policy's window is open now; a blackout is not
	// active now.
	OpenNow bool
	// NextChange: when that changes (nil: not within the horizon).
	NextChange *time.Time
}

func (s *Service) view(p *swdom.Policy) PolicyView {
	now := s.now()
	src := swdom.PolicySource(p)
	d := swdom.Decide([]swdom.Source{src}, swdom.TierIntrusive, now)
	v := PolicyView{Policy: p, OpenNow: d.Open}
	if d.Open {
		v.NextChange = d.ClosesAt
	} else {
		v.NextChange = d.NextOpen
	}
	return v
}

func parseID(raw string, notFound error) (shared.ID, error) {
	id, err := shared.IDFromString(raw)
	if err != nil {
		return shared.ID{}, notFound
	}
	return id, nil
}

// List returns the tenant's policies.
func (s *Service) List(ctx context.Context, tenantID shared.ID) ([]PolicyView, error) {
	ps, err := s.repo.List(ctx, tenantID, swdom.Filter{})
	if err != nil {
		return nil, err
	}
	out := make([]PolicyView, 0, len(ps))
	for _, p := range ps {
		out = append(out, s.view(p))
	}
	return out, nil
}

// Get returns one policy of the tenant.
func (s *Service) Get(ctx context.Context, tenantID shared.ID, id string) (PolicyView, error) {
	pid, err := parseID(id, swdom.ErrNotFound)
	if err != nil {
		return PolicyView{}, err
	}
	p, err := s.repo.GetByID(ctx, tenantID, pid)
	if err != nil {
		return PolicyView{}, err
	}
	return s.view(p), nil
}

// Create validates and stores a policy.
func (s *Service) Create(ctx context.Context, tenantID shared.ID, spec swdom.Spec, actx auditapp.AuditContext) (PolicyView, error) {
	var createdBy *shared.ID
	if uid, err := shared.IDFromString(actx.ActorID); err == nil {
		createdBy = &uid
	}
	p, err := swdom.NewPolicy(tenantID, spec, createdBy, s.now())
	if err != nil {
		return PolicyView{}, err
	}
	n, err := s.repo.Count(ctx, tenantID)
	if err != nil {
		return PolicyView{}, err
	}
	if n >= swdom.MaxPoliciesPerTenant {
		return PolicyView{}, swdom.ErrTooMany
	}
	if err := s.refs.CheckReferences(ctx, tenantID, p.Selector); err != nil {
		return PolicyView{}, err
	}
	if err := s.repo.Create(ctx, p); err != nil {
		return PolicyView{}, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanWindowPolicyCreated, auditdom.ResourceTypeScanWindowPolicy, p.ID.String()).
		WithResourceName(p.Name).
		WithMessage(fmt.Sprintf("Scan window policy '%s' created", p.Name)).
		WithMetadata("policy", describe(p)))
	s.release(ctx, tenantID)
	return s.view(p), nil
}

// Update applies mutate to the policy's settings and stores them.
func (s *Service) Update(ctx context.Context, tenantID shared.ID, id string, mutate func(*swdom.Spec), actx auditapp.AuditContext) (PolicyView, error) {
	pid, err := parseID(id, swdom.ErrNotFound)
	if err != nil {
		return PolicyView{}, err
	}
	p, err := s.repo.GetByID(ctx, tenantID, pid)
	if err != nil {
		return PolicyView{}, err
	}
	before := describe(p)
	spec := p.Spec()
	mutate(&spec)
	if err := p.Update(spec, s.now()); err != nil {
		return PolicyView{}, err
	}
	if err := s.refs.CheckReferences(ctx, tenantID, p.Selector); err != nil {
		return PolicyView{}, err
	}
	if err := s.repo.Update(ctx, p); err != nil {
		return PolicyView{}, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanWindowPolicyUpdated, auditdom.ResourceTypeScanWindowPolicy, p.ID.String()).
		WithResourceName(p.Name).
		WithMessage(fmt.Sprintf("Scan window policy '%s' updated", p.Name)).
		WithMetadata("before", before).
		WithMetadata("after", describe(p)))
	s.release(ctx, tenantID)
	return s.view(p), nil
}

// Delete removes a policy.
func (s *Service) Delete(ctx context.Context, tenantID shared.ID, id string, actx auditapp.AuditContext) error {
	pid, err := parseID(id, swdom.ErrNotFound)
	if err != nil {
		return err
	}
	p, err := s.repo.GetByID(ctx, tenantID, pid)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tenantID, pid); err != nil {
		return err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanWindowPolicyDeleted, auditdom.ResourceTypeScanWindowPolicy, p.ID.String()).
		WithResourceName(p.Name).
		WithMessage(fmt.Sprintf("Scan window policy '%s' deleted", p.Name)).
		WithMetadata("policy", describe(p)))
	s.release(ctx, tenantID)
	return nil
}

// release makes the tenant's deferred jobs due again (best effort: they are
// re-evaluated within an hour anyway).
func (s *Service) release(ctx context.Context, tenantID shared.ID) {
	if s.holds == nil {
		return
	}
	if _, err := s.holds.ReleaseWindowHolds(ctx, tenantID); err != nil {
		s.logger.Warn("deferred jobs not released after a scan window change", "tenant_id", tenantID.String(), "error", err)
	}
}

// maxPreviewAssets bounds the assets a preview lists.
const maxPreviewAssets = 50

// Preview is what a draft policy would select and when it opens.
type Preview struct {
	// AssetDimensions: the selector selects by asset attributes, so
	// MatchedAssets is meaningful. Scope entries, zones and programs are
	// applied to targets at dispatch and are not listed.
	AssetDimensions bool                `json:"asset_dimensions"`
	MatchedAssets   int                 `json:"matched_assets"`
	Assets          []swdom.TargetAsset `json:"assets"`
	// Truncated: the caller sees only part of the organization's assets,
	// or more matched than were read.
	Truncated bool `json:"truncated"`
	// OpenNow and Openings are the policy's own windows (for a blackout:
	// when it is NOT active).
	OpenNow  bool           `json:"open_now"`
	Openings []swdom.Window `json:"openings"`
}

// PreviewPolicy evaluates a draft policy without storing it.
func (s *Service) PreviewPolicy(ctx context.Context, tenantID shared.ID, spec swdom.Spec) (*Preview, error) {
	p, err := swdom.NewPolicy(tenantID, spec, nil, s.now())
	if err != nil {
		return nil, err
	}
	if err := s.refs.CheckReferences(ctx, tenantID, p.Selector); err != nil {
		return nil, err
	}
	now := s.now()
	src := swdom.PolicySource(p)
	out := &Preview{Assets: []swdom.TargetAsset{}, AssetDimensions: p.Selector.UsesAssets()}
	out.OpenNow = swdom.Decide([]swdom.Source{src}, swdom.TierIntrusive, now).Open
	out.Openings = swdom.Openings([]swdom.Source{src}, swdom.TierIntrusive, now, 5)
	if out.Openings == nil {
		out.Openings = []swdom.Window{}
	}
	if !out.AssetDimensions || s.assets == nil {
		return out, nil
	}
	total, assets, err := s.assets.MatchingAssets(ctx, tenantID, p.Selector, 1000)
	if err != nil {
		return nil, err
	}
	visible, full, err := s.visibleAssets(ctx, tenantID, assets)
	if err != nil {
		return nil, err
	}
	out.MatchedAssets = total
	if !full {
		out.MatchedAssets = len(visible)
		out.Truncated = true
	} else if total > len(assets) {
		out.Truncated = true
	}
	out.Assets = visible[:min(len(visible), maxPreviewAssets)]
	return out, nil
}

// visibleAssets keeps the assets the caller may see; full is true for a
// caller with full data access.
func (s *Service) visibleAssets(ctx context.Context, tenantID shared.ID, in []swdom.TargetAsset) ([]swdom.TargetAsset, bool, error) {
	if s.scope == nil {
		return []swdom.TargetAsset{}, false, nil // fail closed: list nothing
	}
	full, err := s.scope.FullDataCaller(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
	if full {
		return in, true, nil
	}
	ids := make([]shared.ID, 0, len(in))
	for _, a := range in {
		if id, err := shared.IDFromString(a.ID); err == nil {
			ids = append(ids, id)
		}
	}
	allowed, err := s.scope.FilterForCaller(ctx, tenantID, ids)
	if err != nil {
		return nil, false, err
	}
	out := make([]swdom.TargetAsset, 0, len(in))
	for _, a := range in {
		if id, err := shared.IDFromString(a.ID); err == nil && allowed(id) {
			out = append(out, a)
		}
	}
	return out, false, nil
}

// EvaluateInput asks what the windows mean for targets and assets now.
type EvaluateInput struct {
	TenantID shared.ID
	Targets  []string
	AssetIDs []string
	// Tier of the work (default: active).
	Tier *int
	// ScanZoneID: the zone the work would run in (zone policies apply
	// only with it).
	ScanZoneID *shared.ID
}

// TargetDecision is the decision for one target.
type TargetDecision struct {
	Target   string        `json:"target"`
	AssetID  string        `json:"asset_id,omitempty"`
	Governed bool          `json:"governed"`
	Open     bool          `json:"open"`
	NextOpen *time.Time    `json:"next_open_at,omitempty"`
	Never    bool          `json:"never"`
	ClosesAt *time.Time    `json:"closes_at,omitempty"`
	Blocking []swdom.Block `json:"blocking"`
	// Governing: every window that applies to the target.
	Governing []swdom.Ref `json:"governing"`
	// RateLimitRPS: the rate cap inside the window (0: none).
	RateLimitRPS int `json:"rate_limit_rps,omitempty"`
}

// maxEvaluate bounds one evaluation.
const maxEvaluate = 200

// Evaluate answers, per target and per asset, whether work may run now, why
// not and when next. Assets the caller may not see are not found.
func (s *Service) Evaluate(ctx context.Context, in EvaluateInput) ([]TargetDecision, error) {
	if len(in.Targets)+len(in.AssetIDs) == 0 {
		return []TargetDecision{}, nil
	}
	if len(in.Targets)+len(in.AssetIDs) > maxEvaluate {
		return nil, fmt.Errorf("%w: at most %d targets and assets", shared.ErrValidation, maxEvaluate)
	}
	tier := swdom.TierActive
	if in.Tier != nil {
		if *in.Tier < swdom.TierAll || *in.Tier > swdom.TierIntrusive {
			return nil, fmt.Errorf("%w: tier must be 0, 1 or 2", shared.ErrValidation)
		}
		tier = *in.Tier
	}
	type item struct{ target, assetID string }
	items := make([]item, 0, len(in.Targets)+len(in.AssetIDs))
	for _, t := range in.Targets {
		items = append(items, item{target: t})
	}
	if len(in.AssetIDs) > 0 {
		named, err := s.namedAssets(ctx, in.TenantID, in.AssetIDs)
		if err != nil {
			return nil, err
		}
		for _, a := range named {
			items = append(items, item{target: a.name, assetID: a.id})
		}
	}
	targets := make([]string, 0, len(items))
	for _, it := range items {
		targets = append(targets, it.target)
	}
	now := s.now()
	snap, err := s.resolver.Load(ctx, in.TenantID, targets, now)
	if err != nil {
		return nil, err
	}
	out := make([]TargetDecision, 0, len(items))
	for _, it := range items {
		d := swdom.Decide(snap.SourcesFor(it.target, in.ScanZoneID), tier, now)
		td := TargetDecision{Target: it.target, AssetID: it.assetID, Governed: d.Governed, Open: d.Open,
			NextOpen: d.NextOpen, Never: d.Never, ClosesAt: d.ClosesAt, Blocking: d.Blocking,
			Governing: d.Governing, RateLimitRPS: d.RateLimitRPS}
		if td.Blocking == nil {
			td.Blocking = []swdom.Block{}
		}
		if td.Governing == nil {
			td.Governing = []swdom.Ref{}
		}
		out = append(out, td)
	}
	return out, nil
}

type namedAsset struct{ id, name string }

// namedAssets resolves asset ids to names: the tenant's live assets the
// caller may see. Any other id is not found (no existence oracle).
func (s *Service) namedAssets(ctx context.Context, tenantID shared.ID, raw []string) ([]namedAsset, error) {
	if s.assets == nil || s.scope == nil {
		return nil, shared.ErrNotFound
	}
	ids := make([]shared.ID, 0, len(raw))
	for _, r := range raw {
		id, err := shared.IDFromString(r)
		if err != nil {
			return nil, shared.ErrNotFound
		}
		ids = append(ids, id)
	}
	names, err := s.assets.AssetNames(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	allowed, err := s.scope.FilterForCaller(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	out := make([]namedAsset, 0, len(ids))
	for _, id := range ids {
		name, ok := names[id]
		if !ok || !allowed(id) {
			return nil, shared.ErrNotFound
		}
		out = append(out, namedAsset{id: id.String(), name: name})
	}
	return out, nil
}

// ListOverrides returns the tenant's recent overrides.
func (s *Service) ListOverrides(ctx context.Context, tenantID shared.ID) ([]*swdom.Override, error) {
	return s.overrides.ListRecent(ctx, tenantID, 50)
}

// OverrideInput starts an override.
type OverrideInput struct {
	TenantID        shared.ID
	UserID          string
	PolicyID        string // "": every policy
	Reason          string
	DurationMinutes int
	TOTPCode        string
}

// CreateOverride suspends one or every policy of the tenant after checking a
// fresh authenticator code of the caller. Program windows are never
// suspended. Audited (high) and notified to every owner and administrator.
func (s *Service) CreateOverride(ctx context.Context, in OverrideInput, actx auditapp.AuditContext) (*swdom.Override, error) {
	uid, err := shared.IDFromString(in.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: an override needs a signed-in member", shared.ErrForbidden)
	}
	var policyID *shared.ID
	var policyName string
	if in.PolicyID != "" {
		if len(in.PolicyID) > 8 && in.PolicyID[:8] == "program:" {
			return nil, swdom.ErrOverrideProgram
		}
		pid, err := parseID(in.PolicyID, swdom.ErrNotFound)
		if err != nil {
			return nil, err
		}
		p, err := s.repo.GetByID(ctx, in.TenantID, pid)
		if err != nil {
			return nil, err
		}
		policyID, policyName = &pid, p.Name
	}
	o, err := swdom.NewOverride(in.TenantID, policyID, in.Reason, time.Duration(in.DurationMinutes)*time.Minute, &uid, s.now())
	if err != nil {
		return nil, err
	}
	if s.totp == nil {
		return nil, shared.NewDomainError("STEP_UP_UNAVAILABLE", "overrides are not available: no second factor check is configured", shared.ErrForbidden)
	}
	if in.TOTPCode == "" {
		return nil, swdom.ErrOverrideBadCode
	}
	if err := s.totp.VerifyFreshTOTP(ctx, uid.String(), in.TOTPCode); err != nil {
		if errors.Is(err, swdom.ErrOverrideBadCode) {
			s.logAudit(ctx, actx, auditapp.NewDeniedEvent(auditdom.ActionScanWindowOverrideRefused, auditdom.ResourceTypeScanWindowOverride, "", "invalid authenticator code").
				WithMessage("Scan window override refused: the authenticator code is not valid"))
		}
		return nil, err
	}
	if err := s.overrides.Create(ctx, o); err != nil {
		return nil, err
	}
	o.PolicyName = policyName
	scope := "every scan window policy"
	if policyID != nil {
		scope = fmt.Sprintf("scan window policy '%s'", policyName)
	}
	until := o.EndsAt.UTC().Format(time.RFC3339)
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanWindowOverrideStarted, auditdom.ResourceTypeScanWindowOverride, o.ID.String()).
		WithResourceName(scope).
		WithMessage(fmt.Sprintf("Scan windows overridden until %s (%s): %s", until, scope, o.Reason)).
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("policy_id", idOrEmpty(policyID)).
		WithMetadata("ends_at", until).
		WithMetadata("reason", o.Reason).
		WithMetadata("second_factor", "totp"))
	s.notify(ctx, in.TenantID, o.ID,
		"Scan windows overridden",
		fmt.Sprintf("%s is suspended until %s. Reason: %s. Bug-bounty program windows still apply.", scope, until, o.Reason))
	s.release(ctx, in.TenantID)
	return o, nil
}

// RevokeOverride ends an active override early.
func (s *Service) RevokeOverride(ctx context.Context, tenantID shared.ID, id, userID string, actx auditapp.AuditContext) error {
	oid, err := parseID(id, swdom.ErrOverrideNotFound)
	if err != nil {
		return err
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return fmt.Errorf("%w: revoking needs a signed-in member", shared.ErrForbidden)
	}
	o, err := s.overrides.GetByID(ctx, tenantID, oid)
	if err != nil {
		return err
	}
	if err := s.overrides.Revoke(ctx, tenantID, oid, uid, s.now()); err != nil {
		return err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScanWindowOverrideRevoked, auditdom.ResourceTypeScanWindowOverride, o.ID.String()).
		WithMessage("Scan window override ended early").
		WithMetadata("policy_id", idOrEmpty(o.PolicyID)))
	s.notify(ctx, tenantID, o.ID, "Scan window override ended", "A scan window override was ended early; the windows apply again.")
	s.release(ctx, tenantID)
	return nil
}

// notify tells every active owner and administrator in the app and puts the
// event on the security-alert channel (best effort: the change is audited).
func (s *Service) notify(ctx context.Context, tenantID, overrideID shared.ID, title, body string) {
	const url = "/settings/scanning/scan-windows"
	if s.admins != nil && s.inApp != nil {
		ids, err := s.admins.ActiveAdminIDs(ctx, tenantID)
		if err != nil {
			s.logger.Warn("override notice: list administrators", "error", logger.SanitizeError(err))
		}
		for _, id := range ids {
			uid := id
			if err := s.inApp.Notify(ctx, notificationdom.NotificationParams{
				TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
				NotificationType: notificationdom.TypeScanWindowOverride, Title: title, Body: body, Severity: "high",
				ResourceType: "scan_window_override", URL: url,
			}); err != nil {
				s.logger.Warn("override notice: in-app notification", "error", logger.SanitizeError(err))
			}
		}
	}
	if s.channels != nil {
		var agg *uuid.UUID
		if id, err := uuid.Parse(overrideID.String()); err == nil {
			agg = &id
		}
		if err := s.channels.Enqueue(ctx, outbox.EnqueueParams{
			TenantID: tenantID, EventType: string(integration.EventTypeSecurityAlert), AggregateType: "scan_window_override",
			AggregateID: agg, Title: title, Body: body, Severity: "high", URL: url,
		}); err != nil {
			s.logger.Warn("override notice: enqueue", "error", logger.SanitizeError(err))
		}
	}
}

func idOrEmpty(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// describe is the audit view of a policy.
func describe(p *swdom.Policy) map[string]any {
	return map[string]any{
		"kind": string(p.Kind), "min_tier": p.MinTier, "enabled": p.Enabled, "timezone": p.Timezone,
		"selector": p.Selector, "slots": p.Slots, "one_offs": p.OneOffs, "grace_minutes": p.GraceMinutes,
		"rate_limit_rps": p.RateLimitRPS, "max_concurrent": p.MaxConcurrent,
	}
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to record audit event", "action", string(event.Action), "error", err)
	}
}

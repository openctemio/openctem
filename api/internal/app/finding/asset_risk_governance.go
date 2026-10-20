package finding

// Governance of edits that lower an asset's risk inputs
// (docs/architecture/asset-risk-governance.md).
//
// Threat model: exposure, criticality and the crown-jewel flag decide the
// priority class of every finding on the asset. Whoever can edit an asset
// (members, the asset's own owner) could lower them and so shorten their own
// queue. Raising risk is free. An edit that would LOWER the class of an open
// P0/P1 finding on the asset first shows its impact, then is decided under the
// organization's approval policy (the same evaluator, level, approver pool,
// step-up and sign-off rows as a false positive): one person may decide it
// alone only where the policy lets them; otherwise it waits as a request and
// the asset keeps its values. The requester and the asset's owners never sign
// off; the request applies only while the asset still has the values it was
// made from, and the change is applied by the same code path as an ordinary
// edit.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

const (
	// maxRiskImpactFindings bounds how many open findings of one asset a
	// simulation classifies.
	maxRiskImpactFindings = 5000
	riskImpactPage        = 1000
	maxRiskReasonRunes    = 1000
)

// AssetRiskApplier writes the lowered inputs of an approved request through
// the same path as an ordinary edit (*asset.AssetService).
type AssetRiskApplier interface {
	ApplyLoweredRiskInputs(ctx context.Context, tenantID, assetID shared.ID, to asset.PriorityInputs, fields []string, actor shared.ID) error
}

// AssetRiskGovernance decides edits that lower an asset's risk inputs.
type AssetRiskGovernance struct {
	v        *VulnerabilityService
	prio     *PriorityClassificationService
	assets   asset.Repository
	requests asset.RiskChangeRequestRepository
	applier  AssetRiskApplier
	logger   *logger.Logger
}

// NewAssetRiskGovernance returns the service. v supplies the approval policy,
// approver directory, notifications, step-up gate and audit trail; prio the
// classifier the simulation runs.
func NewAssetRiskGovernance(v *VulnerabilityService, prio *PriorityClassificationService, assets asset.Repository,
	requests asset.RiskChangeRequestRepository, applier AssetRiskApplier, log *logger.Logger,
) *AssetRiskGovernance {
	return &AssetRiskGovernance{v: v, prio: prio, assets: assets, requests: requests, applier: applier,
		logger: log.With("service", "asset-risk-governance")}
}

// ErrRiskNoEligibleApprover: the change needs a second person and nobody the
// policy allows can approve it.
var ErrRiskNoEligibleApprover = fmt.Errorf("%w: this change needs approval and the organization has no eligible approver; ask an administrator to change the approval policy", shared.ErrConflict)

// riskSim is one simulation: the impact and the finding the policy is
// evaluated on.
type riskSim struct {
	impact asset.RiskImpact
	worst  *vulnerability.Finding
}

// simulate classifies the asset's open findings with the proposed inputs and
// compares each class with its stored one. Read-only.
func (g *AssetRiskGovernance) simulate(ctx context.Context, tenantID shared.ID, a *asset.Asset, proposed asset.PriorityInputs) (*riskSim, error) {
	before := asset.PriorityInputsOf(a)
	sim := &riskSim{impact: asset.RiskImpact{Lowered: asset.LoweredFields(before, proposed), Moves: []asset.RiskClassMove{}}}
	rules, err := g.prio.ruleRepo.ListActiveByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load priority rules: %w", err)
	}
	// A copy of the asset with the proposed inputs; the stored one is not touched.
	clone, err := g.assets.GetByID(ctx, tenantID, a.ID())
	if err != nil {
		return nil, err
	}
	if err := clone.UpdateExposure(proposed.Exposure); err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	if err := clone.UpdateCriticality(proposed.Criticality); err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	clone.SetCrownJewel(proposed.CrownJewel)
	assets := map[shared.ID]*asset.Asset{a.ID(): clone}

	aid := a.ID()
	filter := vulnerability.NewFindingFilter().WithTenantID(tenantID)
	filter.AssetID = &aid
	filter.Statuses = vulnerability.OpenStatuses()
	filter, err = visibleFilter(ctx, g.v.dataScope, tenantID, filter)
	if err != nil {
		return nil, err
	}
	opts := vulnerability.NewFindingListOptions().WithSort(
		pagination.NewSortOption(vulnerability.FindingAllowedSortFields()).Parse("created_at"))
	moves := map[[2]string]int{}
	read := 0
	for pageNum := 1; read < maxRiskImpactFindings; pageNum++ {
		res, err := g.v.findingRepo.List(ctx, filter, opts, pagination.Pagination{Page: pageNum, PerPage: riskImpactPage})
		if err != nil {
			return nil, fmt.Errorf("list open findings: %w", err)
		}
		read += len(res.Data)
		for _, f := range res.Data {
			sim.impact.OpenFindings++
			if f.PriorityClassOverride() {
				sim.impact.ManualOverridesKept++
			}
		}
		for _, fc := range g.prio.enrichAndContextualize(ctx, tenantID, res.Data, assets) {
			old := fc.finding.PriorityClass()
			if old == nil {
				continue
			}
			now := classifyContext(rules, fc.pctx).Class
			if now == *old {
				continue
			}
			moves[[2]string{string(*old), string(now)}]++
			if now > *old { // P3 > P0 as strings: a larger class is less urgent
				sim.impact.ClassDrops++
				if *old == vulnerability.PriorityP0 || *old == vulnerability.PriorityP1 {
					sim.impact.P0P1Drops++
					if worseForPolicy(fc.finding, sim.worst) {
						sim.worst = fc.finding
					}
				}
			} else {
				sim.impact.Raised++
			}
		}
		if len(res.Data) < riskImpactPage {
			break
		}
	}
	for k, n := range moves {
		sim.impact.Moves = append(sim.impact.Moves, asset.RiskClassMove{From: k[0], To: k[1], Count: n})
	}
	slices.SortFunc(sim.impact.Moves, func(x, y asset.RiskClassMove) int {
		if c := strings.Compare(x.From, y.From); c != 0 {
			return c
		}
		return strings.Compare(x.To, y.To)
	})
	if sim.worst != nil {
		sim.impact.WorstFindingID = sim.worst.ID().String()
	}
	return sim, nil
}

// worseForPolicy reports whether f should replace cur as the finding the
// policy is evaluated on: P0 before P1, then the higher severity, KEV first.
func worseForPolicy(f, cur *vulnerability.Finding) bool {
	if cur == nil {
		return true
	}
	rank := func(x *vulnerability.Finding) int {
		r := 0
		if pc := x.PriorityClass(); pc != nil && *pc == vulnerability.PriorityP0 {
			r += 100
		}
		if x.IsInKEV() {
			r += 50
		}
		switch x.Severity() {
		case vulnerability.SeverityCritical:
			r += 4
		case vulnerability.SeverityHigh:
			r += 3
		case vulnerability.SeverityMedium:
			r += 2
		}
		return r
	}
	return rank(f) > rank(cur)
}

func (g *AssetRiskGovernance) loadAsset(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error) {
	return g.assets.GetByID(ctx, tenantID, assetID)
}

// Preview shows the impact of a proposed change and how it would be decided
// for the caller. The route has already checked the asset against the caller's
// data scope.
func (g *AssetRiskGovernance) Preview(ctx context.Context, tenantID, assetID, caller shared.ID, canApprove bool, proposed asset.PriorityInputs) (*asset.RiskPreview, error) {
	a, err := g.loadAsset(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	sim, err := g.simulate(ctx, tenantID, a, proposed)
	if err != nil {
		return nil, err
	}
	out := &asset.RiskPreview{Impact: sim.impact}
	if p, err := g.requests.Pending(ctx, tenantID, assetID); err == nil && p != nil {
		out.PendingRequest = true
	}
	if sim.worst != nil {
		ev, err := g.v.evaluateFindingRequest(ctx, sim.worst, approvalpolicy.KindFalsePositive, caller, false, canApprove)
		if err != nil {
			return nil, err
		}
		out.Approval = &asset.RiskApprovalView{
			Required: !ev.result.SinglePerson(), Tier: string(ev.result.Tier), RequiredApprovals: ev.result.Required,
			Reasons: ev.result.Reasons, EligibleApprovers: len(ev.result.Eligible), Satisfiable: ev.result.Satisfiable(),
			MinNoteLength: ev.result.MinNoteLength, StepUp: ev.result.StepUp,
		}
	}
	return out, nil
}

// GovernInput is one edit that lowers risk inputs.
type GovernInput struct {
	TenantID, AssetID shared.ID
	// Before is what the asset has; After what the edit sets.
	Before, After asset.PriorityInputs
	Actor         shared.ID
	CanApprove    bool
	Reason        string
	Audit         audit.AuditContext
}

// GovernOutcome is the decision. Held is set when the lowered fields wait for
// approval (the caller must not apply them); otherwise the edit applies.
type GovernOutcome struct {
	Held   *asset.RiskChangeRequest
	Impact asset.RiskImpact
}

// Govern decides an edit that lowers risk inputs: free when it drops no open
// P0/P1 finding; otherwise by the organization's approval policy, as a person
// deciding alone (audited at High severity) or as a pending request.
func (g *AssetRiskGovernance) Govern(ctx context.Context, in GovernInput) (GovernOutcome, error) {
	lowered := asset.LoweredFields(in.Before, in.After)
	if len(lowered) == 0 {
		return GovernOutcome{}, nil
	}
	a, err := g.loadAsset(ctx, in.TenantID, in.AssetID)
	if err != nil {
		return GovernOutcome{}, err
	}
	sim, err := g.simulate(ctx, in.TenantID, a, in.After)
	if err != nil {
		return GovernOutcome{}, err
	}
	out := GovernOutcome{Impact: sim.impact}
	if sim.worst == nil {
		return out, nil // lowers no open P0/P1: free
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return out, fmt.Errorf("%w: lowering %s would drop %d open P0/P1 finding(s); a reason is required",
			shared.ErrValidation, strings.Join(lowered, ", "), sim.impact.P0P1Drops)
	}
	if utf8.RuneCountInString(reason) > maxRiskReasonRunes {
		return out, fmt.Errorf("%w: the reason must be at most %d characters", shared.ErrValidation, maxRiskReasonRunes)
	}
	if p, err := g.requests.Pending(ctx, in.TenantID, in.AssetID); err != nil {
		return out, err
	} else if p != nil {
		return out, asset.ErrRiskRequestPending
	}
	ev, err := g.v.evaluateFindingRequest(ctx, sim.worst, approvalpolicy.KindFalsePositive, in.Actor, false, in.CanApprove)
	if err != nil {
		return out, err
	}
	meta := map[string]any{
		"lowered_fields": lowered, "reason": reason, "p0_p1_drops": sim.impact.P0P1Drops,
		"class_drops": sim.impact.ClassDrops, "tier": string(ev.result.Tier),
		"before": inputsMeta(in.Before), "after": inputsMeta(in.After),
	}
	if ev.result.SinglePerson() {
		g.auditAsset(ctx, in.Audit, auditdom.ActionAssetRiskLowered, in.TenantID, in.AssetID, a.Name(),
			"Lowered the risk inputs of an asset that has open P0/P1 findings", meta, auditdom.SeverityHigh)
		return out, nil
	}
	if !ev.result.Satisfiable() {
		return out, ErrRiskNoEligibleApprover
	}
	if n := utf8.RuneCountInString(reason); n < ev.result.MinNoteLength {
		return out, fmt.Errorf("%w: this change needs a reason of at least %d characters (%s tier)",
			shared.ErrValidation, ev.result.MinNoteLength, ev.result.Tier)
	}
	now := time.Now().UTC()
	within := ev.result.DecideWithin
	if within <= 0 {
		within = asset.DefaultRiskDecisionWindow
	}
	required := max(ev.result.Required, 1)
	impactJSON, _ := json.Marshal(sim.impact)
	by := in.Actor
	req := &asset.RiskChangeRequest{
		ID: shared.NewID(), TenantID: in.TenantID, AssetID: in.AssetID,
		Requested: in.After, Previous: in.Before, Lowered: lowered, Reason: reason,
		RequestedBy: &by, Status: asset.RiskRequestPending, Tier: string(ev.result.Tier), RequiredApprovals: required,
		Impact: impactJSON, DecideBy: now.Add(within), CreatedAt: now,
	}
	if err := g.requests.Create(ctx, req); err != nil {
		return out, err
	}
	meta["request_id"] = req.ID.String()
	g.auditAsset(ctx, in.Audit, auditdom.ActionAssetRiskRequested, in.TenantID, in.AssetID, a.Name(),
		"Asked to lower the risk inputs of an asset that has open P0/P1 findings", meta, auditdom.SeverityMedium)
	g.notifyApprovers(ctx, a, req, ev.result.Eligible)
	out.Held = req
	return out, nil
}

func inputsMeta(p asset.PriorityInputs) map[string]any {
	return map[string]any{"exposure": string(p.Exposure), "criticality": string(p.Criticality), "crown_jewel": p.CrownJewel}
}

func (g *AssetRiskGovernance) auditAsset(ctx context.Context, actx audit.AuditContext, action auditdom.Action,
	tenantID, assetID shared.ID, name, msg string, meta map[string]any, sev auditdom.Severity,
) {
	if g.v.auditService == nil {
		return
	}
	if actx.TenantID == "" {
		actx.TenantID = tenantID.String()
	}
	event := audit.NewSuccessEvent(action, auditdom.ResourceTypeAsset, assetID.String()).
		WithResourceName(name).WithMessage(msg).WithSeverity(sev)
	for k, v := range meta {
		event = event.WithMetadata(k, v)
	}
	if err := g.v.auditService.LogEvent(ctx, actx, event); err != nil {
		g.logger.Warn("asset risk audit", "error", logger.SanitizeError(err))
	}
}

// notifyApprovers tells the people the policy lets decide the request
// (in-app; never the requester or an owner of the asset).
func (g *AssetRiskGovernance) notifyApprovers(ctx context.Context, a *asset.Asset, req *asset.RiskChangeRequest, eligible []shared.ID) {
	if g.v.approvalInApp == nil {
		return
	}
	title := "Asset risk change waiting for approval"
	body := fmt.Sprintf("%s: lowers %s", oneLineTitle(a.Name()), strings.Join(req.Lowered, ", "))
	url := "/assets/" + a.ID().String()
	for _, uid := range eligible {
		if req.RequestedBy != nil && uid == *req.RequestedBy {
			continue
		}
		user, aid := uid, a.ID()
		if err := g.v.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: req.TenantID, Audience: notificationdom.AudienceUser, AudienceID: &user,
			NotificationType: notificationdom.TypeFindingApproval, Title: title, Body: body,
			Severity: notificationdom.SeverityMedium, ResourceType: "asset", ResourceID: &aid, URL: url,
		}); err != nil {
			g.logger.Warn("asset risk request: in-app notification", "error", logger.SanitizeError(err))
		}
	}
}

// PendingRequest returns the asset's pending request, or nil. The caller has
// already checked the asset against its data scope.
func (g *AssetRiskGovernance) PendingRequest(ctx context.Context, tenantID, assetID shared.ID) (*asset.RiskChangeRequest, error) {
	return g.requests.Pending(ctx, tenantID, assetID)
}

// DecideRiskRequestInput names a request and who acts on it.
type DecideRiskRequestInput struct {
	TenantID  string
	AssetID   string
	RequestID string
	ActorID   string
	// Note is the reason of a rejection.
	Note  string
	Audit audit.AuditContext
}

// RiskDecisionResult is the request after the call and whether the change
// was applied.
type RiskDecisionResult struct {
	Request *asset.RiskChangeRequest
	Applied bool
}

func (g *AssetRiskGovernance) load(ctx context.Context, in *DecideRiskRequestInput) (*asset.Asset, *asset.RiskChangeRequest, shared.ID, error) {
	if in.Audit.ActorID == "" {
		in.Audit.ActorID = in.ActorID
	}
	tid, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, nil, shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(in.AssetID)
	if err != nil {
		return nil, nil, shared.ID{}, shared.ErrNotFound
	}
	actor, err := shared.IDFromString(in.ActorID)
	if err != nil {
		return nil, nil, shared.ID{}, fmt.Errorf("%w: a decision needs an authenticated person", shared.ErrValidation)
	}
	rid, err := shared.IDFromString(in.RequestID)
	if err != nil {
		return nil, nil, shared.ID{}, fmt.Errorf("%w: invalid request id", shared.ErrValidation)
	}
	a, err := g.assets.GetByID(ctx, tid, aid)
	if err != nil {
		return nil, nil, shared.ID{}, err
	}
	req, err := g.requests.Get(ctx, tid, rid)
	if err != nil {
		return nil, nil, shared.ID{}, err
	}
	if req.AssetID != a.ID() {
		return nil, nil, shared.ID{}, fmt.Errorf("%w: risk change request not found", shared.ErrNotFound)
	}
	return a, req, actor, nil
}

// requestStale reports whether the asset no longer has the values of the
// lowered fields the request was made from.
func requestStale(req *asset.RiskChangeRequest, cur asset.PriorityInputs) bool {
	for _, f := range req.Lowered {
		switch f {
		case "exposure":
			if cur.Exposure != req.Previous.Exposure {
				return true
			}
		case "criticality":
			if cur.Criticality != req.Previous.Criticality {
				return true
			}
		case "crown_jewel":
			if cur.CrownJewel != req.Previous.CrownJewel {
				return true
			}
		}
	}
	return false
}

// ApproveRequest records the caller's approval under the policy evaluated now
// and applies the change when it is the last approval needed. The route needs
// findings:approve and the asset in the caller's data scope.
func (g *AssetRiskGovernance) ApproveRequest(ctx context.Context, in DecideRiskRequestInput) (*RiskDecisionResult, error) {
	a, req, approver, err := g.load(ctx, &in)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if req.Status != asset.RiskRequestPending {
		return nil, fmt.Errorf("%w: this request is %s", shared.ErrConflict, req.Status)
	}
	if !req.IsDecidable(now) {
		return nil, asset.ErrRiskRequestOverdue
	}
	if req.RequestedBy != nil && *req.RequestedBy == approver {
		return nil, asset.ErrRiskSelfApproval
	}
	if requestStale(req, asset.PriorityInputsOf(a)) {
		return nil, asset.ErrRiskRequestStale
	}
	worst, err := g.evaluationFinding(ctx, req, a)
	if err != nil {
		return nil, err
	}
	prior, err := g.requests.Signoffs(ctx, req.TenantID, req.ID)
	if err != nil {
		return nil, err
	}
	known := []shared.ID{approver}
	for _, p := range prior {
		known = append(known, p.UserID)
	}
	requester := shared.ID{}
	if req.RequestedBy != nil {
		requester = *req.RequestedBy
	}
	ev, err := g.v.evaluateFindingRequest(ctx, worst, approvalpolicy.KindFalsePositive, requester, false, false, known...)
	if err != nil {
		return nil, err
	}
	res := ev.result
	if res.Tier == approvalpolicy.TierSingle {
		// The policy relaxed since the request: one other eligible person
		// still decides it (it was made as a request).
		res.Tier, res.Required = approvalpolicy.TierPeer, 1
	}
	if _, err := res.Sign(approver, prior); err != nil {
		return nil, err
	}
	if res.StepUp {
		if err := g.v.requireApproverStepUp(ctx, approver); err != nil {
			return nil, err
		}
	}
	rec := asset.RiskSignoff{UserID: approver, PoolFallback: res.PoolFallback, StepUp: res.StepUp}
	for _, id := range res.EligiblePool {
		rec.SecurityPool = rec.SecurityPool || id == approver
	}
	applied, err := g.requests.SignOff(ctx, req.TenantID, req.ID, rec,
		func(prior []approvalpolicy.Signoff) (bool, error) { return res.Sign(approver, prior) },
		func(ctx context.Context) error {
			// Only the last approval changes the asset, and only while it
			// still has the values the request was made from.
			cur, err := g.assets.GetByID(ctx, req.TenantID, req.AssetID)
			if err != nil {
				return err
			}
			if requestStale(req, asset.PriorityInputsOf(cur)) {
				return asset.ErrRiskRequestStale
			}
			author := approver
			if req.RequestedBy != nil {
				author = *req.RequestedBy
			}
			return g.applier.ApplyLoweredRiskInputs(ctx, req.TenantID, req.AssetID, req.Requested, req.Lowered, author)
		})
	if err != nil {
		return nil, err
	}
	meta := map[string]any{
		"request_id": req.ID.String(), "lowered_fields": req.Lowered, "reason": req.Reason,
		"approved_by": approver.String(), "approvals_required": res.Required,
		"before": inputsMeta(req.Previous), "after": inputsMeta(req.Requested),
	}
	if !applied {
		g.auditAsset(ctx, in.Audit, auditdom.ActionAssetRiskSigned, req.TenantID, req.AssetID, a.Name(), "Approved a risk change (more approvals needed)", meta, auditdom.SeverityMedium)
		pending, err := g.requests.Get(ctx, req.TenantID, req.ID)
		if err != nil {
			return nil, err
		}
		return &RiskDecisionResult{Request: pending}, nil
	}
	g.auditAsset(ctx, in.Audit, auditdom.ActionAssetRiskApproved, req.TenantID, req.AssetID, a.Name(),
		"Approved lowering the risk inputs of an asset that has open P0/P1 findings", meta, auditdom.SeverityHigh)
	done, err := g.requests.Get(ctx, req.TenantID, req.ID)
	if err != nil {
		return nil, err
	}
	return &RiskDecisionResult{Request: done, Applied: true}, nil
}

// evaluationFinding is the finding the policy is evaluated on: the one the
// request was made for when it can still be read on this asset, else the
// worst one that would drop now; none means the request no longer applies.
func (g *AssetRiskGovernance) evaluationFinding(ctx context.Context, req *asset.RiskChangeRequest, a *asset.Asset) (*vulnerability.Finding, error) {
	var impact asset.RiskImpact
	if err := json.Unmarshal(req.Impact, &impact); err == nil && impact.WorstFindingID != "" {
		if fid, err := shared.IDFromString(impact.WorstFindingID); err == nil {
			f, err := g.v.findingRepo.GetByID(ctx, req.TenantID, fid)
			if err == nil && f.AssetID() == req.AssetID {
				return f, nil
			}
			if err != nil && !errors.Is(err, shared.ErrNotFound) {
				return nil, err
			}
		}
	}
	sim, err := g.simulate(ctx, req.TenantID, a, req.Requested)
	if err != nil {
		return nil, err
	}
	if sim.worst == nil {
		return nil, asset.ErrRiskRequestStale
	}
	return sim.worst, nil
}

// RejectRequest rejects a pending request with a note. The route needs
// findings:approve; the requester withdraws instead.
func (g *AssetRiskGovernance) RejectRequest(ctx context.Context, in DecideRiskRequestInput) (*RiskDecisionResult, error) {
	a, req, actor, err := g.load(ctx, &in)
	if err != nil {
		return nil, err
	}
	note := strings.TrimSpace(in.Note)
	if note == "" {
		return nil, fmt.Errorf("%w: a rejection needs a reason", shared.ErrValidation)
	}
	if req.RequestedBy != nil && *req.RequestedBy == actor {
		return nil, fmt.Errorf("%w: withdraw your own request instead of rejecting it", shared.ErrForbidden)
	}
	return g.closeRequest(ctx, a, req, actor, asset.RiskRequestRejected, note, nil, in.Audit)
}

// CancelRequest lets the requester withdraw their own pending request.
func (g *AssetRiskGovernance) CancelRequest(ctx context.Context, in DecideRiskRequestInput) (*RiskDecisionResult, error) {
	a, req, actor, err := g.load(ctx, &in)
	if err != nil {
		return nil, err
	}
	if req.RequestedBy == nil || *req.RequestedBy != actor {
		return nil, fmt.Errorf("%w: only the requester withdraws a request", shared.ErrForbidden)
	}
	return g.closeRequest(ctx, a, req, actor, asset.RiskRequestCanceled, strings.TrimSpace(in.Note), &actor, in.Audit)
}

func (g *AssetRiskGovernance) closeRequest(ctx context.Context, a *asset.Asset, req *asset.RiskChangeRequest, actor shared.ID,
	status asset.RiskRequestStatus, note string, requester *shared.ID, actx audit.AuditContext,
) (*RiskDecisionResult, error) {
	if err := g.requests.Close(ctx, req.TenantID, req.ID, status, actor, note, requester); err != nil {
		return nil, err
	}
	g.auditAsset(ctx, actx, auditdom.ActionAssetRiskRequestClosed, req.TenantID, req.AssetID, a.Name(), "Closed a risk change request ("+string(status)+")",
		map[string]any{"request_id": req.ID.String(), "status": string(status), "lowered_fields": req.Lowered, "note": note}, auditdom.SeverityMedium)
	closed, err := g.requests.Get(ctx, req.TenantID, req.ID)
	if err != nil {
		return nil, err
	}
	return &RiskDecisionResult{Request: closed}, nil
}

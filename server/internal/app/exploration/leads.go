package exploration

// People and leads (docs/architecture/exploration.md, "Approvals and
// people"): reading leads within the caller's data scope, opening a lead by
// hand, approving and dismissing. The route gates the permission (and
// step-up for approval); this service decides on the object: tenant from
// the principal, the lead's subject in the caller's data scope (out of scope
// answers not found), and the state machine.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	assetdom "github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// MaxBulk bounds one approve or dismiss call.
const MaxBulk = 100

// ScopeResolver resolves the request caller's data scope (nil: unrestricted;
// an unwired resolver is an error, never unrestricted). ViewerScope also
// says whether a restricted caller may read organization-wide figures.
type ScopeResolver interface {
	ResolveStrict(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error)
	ViewerScope(ctx context.Context, tenantID shared.ID) (*shared.DataScope, bool, error)
}

// SubjectReader reads an asset within the request caller's data scope.
type SubjectReader interface {
	GetAssetInCallerScope(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error)
}

// LeadService serves people.
type LeadService struct {
	repo    exploration.Repository
	rollups exploration.RollupStore
	scope   ScopeResolver
	assets  SubjectReader
	sw      ActiveSwitch
	audit   Auditor
	logger  *logger.Logger
	now     func() time.Time
}

// NewLeadService creates the service.
func NewLeadService(repo exploration.Repository, scope ScopeResolver, assets SubjectReader, sw ActiveSwitch, audit Auditor, log *logger.Logger) *LeadService {
	rollups, _ := repo.(exploration.RollupStore)
	return &LeadService{repo: repo, rollups: rollups, scope: scope, assets: assets, sw: sw, audit: audit,
		logger: log.With("component", "exploration-leads"), now: time.Now}
}

// Person is the signed-in person acting.
type Person struct {
	UserID shared.ID
	// Scans: the person may read scan runs (scans:read); a run a lead was
	// dispatched as is shown only then.
	Scans bool
	Actx  auditapp.AuditContext
}

// Groups of the Exploration page.
const (
	GroupWaiting = "waiting"
	GroupNext    = "next"
	GroupRunning = "running"
	GroupDone    = "done"
)

// GroupStates maps a page group to its lead states.
func GroupStates(group string) ([]exploration.LeadState, bool) {
	switch group {
	case GroupWaiting:
		return []exploration.LeadState{exploration.StateAwaitingApproval, exploration.StateProposed, exploration.StateBlocked}, true
	case GroupNext:
		return []exploration.LeadState{exploration.StateOpen}, true
	case GroupRunning:
		return []exploration.LeadState{exploration.StateRunning}, true
	case GroupDone:
		return []exploration.LeadState{exploration.StateDone, exploration.StateRefuted, exploration.StateExhausted,
			exploration.StateDismissed, exploration.StateSuperseded}, true
	case "":
		return nil, true
	}
	return nil, false
}

// ListInput selects leads.
type ListInput struct {
	Group   string
	AssetID string
	Before  *time.Time
	Limit   int
}

// List reads leads within the caller's data scope.
func (s *LeadService) List(ctx context.Context, tenantID shared.ID, in ListInput) ([]*exploration.Lead, error) {
	states, ok := GroupStates(in.Group)
	if !ok {
		return nil, fmt.Errorf("%w: unknown group", shared.ErrValidation)
	}
	scope, err := s.scope.ResolveStrict(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	f := exploration.LeadFilter{States: states, Scope: scope, Before: in.Before, Limit: in.Limit}
	if in.AssetID != "" {
		id, err := shared.IDFromString(in.AssetID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset id", shared.ErrValidation)
		}
		f.SubjectAssetID = &id
	}
	return s.repo.ListLeads(ctx, tenantID, f)
}

// Detail is one lead with its links and verdicts as the caller may see them.
type Detail struct {
	Lead     *exploration.Lead
	Links    []exploration.Link
	Verdicts []exploration.Verdict
}

// readLead reads one lead within the caller's data scope.
func (s *LeadService) readLead(ctx context.Context, tenantID shared.ID, id string) (*exploration.Lead, error) {
	leadID, err := shared.IDFromString(id)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	scope, err := s.scope.ResolveStrict(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.repo.GetLead(ctx, tenantID, leadID, scope)
}

// Get reads one lead with its links and verdicts. Every link end of a lead
// is its subject asset, a finding on the subject asset, another lead or a
// run, so the subject's scope covers them; a run is shown with scans:read
// only (its id is cleared otherwise, the kind and effect stay).
func (s *LeadService) Get(ctx context.Context, tenantID shared.ID, id string, p Person) (*Detail, error) {
	l, err := s.readLead(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	links, err := s.repo.Links(ctx, tenantID, l.ID)
	if err != nil {
		return nil, err
	}
	for i := range links {
		if links[i].EndKind == exploration.EndScanRun && !p.Scans {
			links[i].EndID = nil
		}
	}
	verdicts, err := s.repo.Verdicts(ctx, tenantID, l.ID)
	if err != nil {
		return nil, err
	}
	return &Detail{Lead: l, Links: links, Verdicts: verdicts}, nil
}

// OpenInput is a person's question.
type OpenInput struct {
	LeadType  string
	AssetID   string
	Rationale string
}

// ErrAlreadyAsked: a live lead already asks this question.
var ErrAlreadyAsked = fmt.Errorf("%w: this question is already open", shared.ErrConflict)

// ErrTooManyLeads: the subject or the exploration is at its cap.
var ErrTooManyLeads = fmt.Errorf("%w: too many open questions", shared.ErrConflict)

// Open opens a lead by hand on an asset in the caller's data scope, with the
// catalog's action for the asset's type. The tier decides its first state
// exactly as for a rule's lead.
func (s *LeadService) Open(ctx context.Context, tenantID shared.ID, p Person, in OpenInput) (*exploration.Lead, error) {
	lt, ok := exploration.LookupLeadType(strings.TrimSpace(in.LeadType))
	if !ok {
		return nil, fmt.Errorf("%w: unknown lead type", shared.ErrValidation)
	}
	a, err := s.assets.GetAssetInCallerScope(ctx, tenantID.String(), in.AssetID)
	if err != nil {
		return nil, err
	}
	action, ok := lt.ActionFor(a.Type(), a.SubType())
	if !ok {
		return nil, fmt.Errorf("%w: this question does not apply to this asset type", shared.ErrValidation)
	}
	explorationID, err := s.repo.EnsureContinuous(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	subject, by := a.ID(), p.UserID
	l, err := exploration.NewLead(exploration.NewLeadInput{
		TenantID: tenantID, ExplorationID: explorationID, Type: lt.ID,
		Action: exploration.Action{Capability: action.Capability}, SubjectAssetID: &subject,
		ReasonCode: lt.Reasons[0], Rationale: in.Rationale, Origin: exploration.OriginUser,
		OriginRef: "user:" + p.UserID.String(), Likelihood: lt.Likelihood, CreatedBy: &by,
		AutoActive: autoActive(ctx, s.sw, tenantID),
	})
	if err != nil {
		return nil, err
	}
	if _, err := exploration.CheckCatalog(l); err != nil {
		return nil, err
	}
	if n, err := s.repo.CountLive(ctx, tenantID, explorationID, &subject); err != nil {
		return nil, err
	} else if n >= MaxLiveLeadsPerSubject {
		return nil, ErrTooManyLeads
	}
	if n, err := s.repo.CountLive(ctx, tenantID, explorationID, nil); err != nil {
		return nil, err
	} else if n >= DefaultMaxOpenLeads {
		return nil, ErrTooManyLeads
	}
	created, err := s.repo.OpenLead(ctx, l, []exploration.Link{{EndKind: exploration.EndAsset, EndID: &subject}})
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, ErrAlreadyAsked
	}
	recordLead(ctx, s.audit, s.logger, l, audit.ActionExplorationLeadOpened, p.Actx, nil)
	return l, nil
}

func autoActive(ctx context.Context, sw ActiveSwitch, tenantID shared.ID) bool {
	if sw == nil {
		return false
	}
	on, err := sw.CoverageEnabled(ctx, tenantID)
	return err == nil && on
}

// BulkResult is the outcome per lead id of a bulk call.
type BulkResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Bulk outcome codes.
const (
	BulkNotFound = "not_found"
	BulkState    = "wrong_state"
	BulkChanged  = "changed"
)

func bulkCode(err error) string {
	switch {
	case err == nil:
		return ""
	case shared.IsNotFound(err):
		return BulkNotFound
	case errors.Is(err, exploration.ErrStale):
		return BulkChanged
	}
	return BulkState
}

func checkBulk(ids []string) error {
	if len(ids) == 0 || len(ids) > MaxBulk {
		return fmt.Errorf("%w: between 1 and %d leads", shared.ErrValidation, MaxBulk)
	}
	return nil
}

// Approve lets the leads waiting for a person run. The route requires the
// scan-approve permission and a fresh step-up; each lead must be in the
// caller's data scope and waiting for approval. An intrusive lead is
// approved too, but the system never starts an intrusive step by itself
// (the controller blocks it): approving one records the decision only.
func (s *LeadService) Approve(ctx context.Context, tenantID shared.ID, p Person, ids []string) ([]BulkResult, error) {
	if err := checkBulk(ids); err != nil {
		return nil, err
	}
	out := make([]BulkResult, 0, len(ids))
	for _, id := range ids {
		err := s.approveOne(ctx, tenantID, p, id)
		out = append(out, BulkResult{ID: id, OK: err == nil, Error: bulkCode(err)})
		if err != nil && !shared.IsNotFound(err) && !errors.Is(err, shared.ErrConflict) {
			return out, err
		}
	}
	return out, nil
}

func (s *LeadService) approveOne(ctx context.Context, tenantID shared.ID, p Person, id string) error {
	l, err := s.readLead(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if l.State != exploration.StateAwaitingApproval {
		return exploration.ErrBadTransition
	}
	now := s.now()
	by := p.UserID
	l.ApprovedBy, l.ApprovedAt = &by, &now
	if err := l.Move(exploration.StateOpen, now); err != nil {
		return err
	}
	if err := s.repo.SaveLead(ctx, l); err != nil {
		return err
	}
	recordLead(ctx, s.audit, s.logger, l, audit.ActionExplorationLeadApproved, p.Actx, map[string]any{"from": string(exploration.StateAwaitingApproval)})
	return nil
}

// Dismiss closes live leads without running them.
func (s *LeadService) Dismiss(ctx context.Context, tenantID shared.ID, p Person, ids []string, reason string) ([]BulkResult, error) {
	if err := checkBulk(ids); err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) > exploration.MaxRationale {
		return nil, fmt.Errorf("%w: reason is too long", shared.ErrValidation)
	}
	out := make([]BulkResult, 0, len(ids))
	for _, id := range ids {
		err := s.dismissOne(ctx, tenantID, p, id, reason)
		out = append(out, BulkResult{ID: id, OK: err == nil, Error: bulkCode(err)})
		if err != nil && !shared.IsNotFound(err) && !errors.Is(err, shared.ErrConflict) {
			return out, err
		}
	}
	return out, nil
}

func (s *LeadService) dismissOne(ctx context.Context, tenantID shared.ID, p Person, id, reason string) error {
	l, err := s.readLead(ctx, tenantID, id)
	if err != nil {
		return err
	}
	// A running step cannot be taken back here; it settles from its run.
	if l.State == exploration.StateRunning {
		return exploration.ErrBadTransition
	}
	from := l.State
	if err := l.Move(exploration.StateDismissed, s.now()); err != nil {
		return err
	}
	if err := s.repo.SaveLead(ctx, l); err != nil {
		return err
	}
	recordLead(ctx, s.audit, s.logger, l, audit.ActionExplorationLeadDismissed, p.Actx,
		map[string]any{"from": string(from), metaReason: reason})
	return nil
}

// RefreshEvery is how often Refresh now recomputes the organization's
// figures at most; a call within it returns the figures as they are.
const RefreshEvery = time.Minute

// Summary returns the exploration's figures for the caller. A caller who
// may read organization-wide figures (unrestricted, or a viewer of
// organization dashboards) gets the precomputed rollup with its freshness;
// any other member gets live counts within their data scope.
func (s *LeadService) Summary(ctx context.Context, tenantID shared.ID, refresh bool) (*exploration.Summary, error) {
	if s.rollups == nil {
		return nil, fmt.Errorf("exploration figures are not available")
	}
	explorationID, err := s.repo.EnsureContinuous(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	scope, orgWide, err := s.scope.ViewerScope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if scope.Restricted() && !orgWide {
		return s.rollups.ScopedSummary(ctx, tenantID, explorationID, scope)
	}
	cur, err := s.rollups.Rollup(ctx, tenantID, explorationID)
	if err != nil && !shared.IsNotFound(err) {
		return nil, err
	}
	if cur != nil && (!refresh || s.now().Sub(cur.ComputedAt) < RefreshEvery) {
		return cur, nil
	}
	if err := s.rollups.RefreshRollup(ctx, tenantID, explorationID); err != nil {
		return nil, err
	}
	return s.rollups.Rollup(ctx, tenantID, explorationID)
}

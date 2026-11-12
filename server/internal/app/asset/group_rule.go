package asset

// Asset groups that fill themselves (docs/architecture/smart-asset-groups.md).
//
// A group's members are the assets its rule matches, plus the assets added by
// hand or by a pasted list, minus the assets taken out by hand. The rule is
// evaluated as its editor: inside the data scope the editor holds at
// evaluation time, so a person cannot build a group that pulls in assets they
// cannot see. An editor who left the tenant pauses the rule (its members stay
// as they were) instead of emptying the group.
//
// Threat model: the rule and the pasted list are untrusted input (size,
// syntax and every value validated before use); a group of another tenant or
// an asset outside the caller's scope is never named in an answer (404 or
// "not found"); a change that brings more assets into a group that team scope
// rules or scans use is audited and returned as an impact summary; for a team
// that holds a privileged role it needs the owner and a recent sign-in. A rule
// never authorizes scanning: scans resolve the members at run time and still
// pass the scope gate.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	assetgroupdom "github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// RuleAssetSource is what the rule evaluator reads from the assets
// (*postgres.AssetRepository).
type RuleAssetSource interface {
	MatchingIDs(ctx context.Context, filter assetdom.Filter, afterID string, limit int) ([]shared.ID, error)
	IDsByNames(ctx context.Context, tenantID shared.ID, names []string) (map[string]shared.ID, error)
	GetDisplayInfoByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]assetdom.DisplayInfo, error)
}

// GroupAccessGuard decides who may change a group that teams depend on
// (*accesscontrol.GroupService).
type GroupAccessGuard interface {
	// FlagPrivileged marks the teams that hold a privileged role.
	FlagPrivileged(ctx context.Context, tenantID shared.ID, teams []assetgroupdom.Use) ([]assetgroupdom.Use, error)
	// RequireOwnerStepUp passes only for an owner with a recent sign-in.
	RequireOwnerStepUp(ctx context.Context, tenantID shared.ID, actorID string) error
}

// PasteAssets is what a pasted list needs to create the assets it names that
// do not exist yet.
type PasteAssets struct {
	// Create makes one asset (*AssetService.CreateAsset).
	Create func(ctx context.Context, in CreateAssetInput) (*assetdom.Asset, error)
	// Covered says which of the names the organization's scope covers.
	Covered func(ctx context.Context, tenantID shared.ID, names []string) (map[string]bool, error)
	// HoldCandidates records the created assets the scope does not cover as
	// candidates: out of the inventory and never probed until a person decides.
	HoldCandidates func(ctx context.Context, tenantID shared.ID, created []CreatedPasteAsset) error
}

// CreatedPasteAsset is an asset a paste created.
type CreatedPasteAsset struct {
	ID   shared.ID
	Name string
	Type assetdom.TypeRef
}

// SetRuleStore wires the rule store and the asset reads of the evaluator.
func (s *AssetGroupService) SetRuleStore(store assetgroupdom.RuleStore, assets RuleAssetSource) {
	s.ruleStore = store
	s.ruleAssets = assets
}

// OverrideMemberCap sets the most members a group may hold (default
// assetgroupdom.DefaultMemberCap).
func (s *AssetGroupService) OverrideMemberCap(n int) { s.capOverride = n }

func (s *AssetGroupService) memberCap() int {
	if s.capOverride > 0 {
		return s.capOverride
	}
	return assetgroupdom.DefaultMemberCap
}

// SetAccessGuard wires the owner and step-up check for groups that
// privileged teams use.
func (s *AssetGroupService) SetAccessGuard(g GroupAccessGuard) { s.guard = g }

// SetPasteAssets wires the creation of the missing assets of a pasted list.
func (s *AssetGroupService) SetPasteAssets(p PasteAssets) { s.paste = p }

var (
	ruleValidatorOnce sync.Once
	ruleValidator     *validator.Validator
)

func ruleInputValidator() *validator.Validator {
	ruleValidatorOnce.Do(func() { ruleValidator = validator.New() })
	return ruleValidator
}

// errRulesUnavailable answers a rule request when the store is not wired.
var errRulesUnavailable = fmt.Errorf("%w: group rules are not available", shared.ErrValidation)

// errRuleEditor answers a rule set by a caller that is not a person: a rule
// evaluates inside its editor's data scope, so it needs one.
var errRuleEditor = fmt.Errorf("%w: a group rule needs a signed-in editor; an API key cannot set one", shared.ErrValidation)

// RuleImpact is what a rule change means for the teams and scans that use
// the group.
type RuleImpact struct {
	// Widens is set when the change brings assets into a group that team
	// scope rules or scans use.
	Widens    bool                `json:"widens"`
	WouldJoin int                 `json:"would_join"`
	Teams     []assetgroupdom.Use `json:"teams"`
	Scans     []assetgroupdom.Use `json:"scans"`
	Privilege bool                `json:"privileged_team"`
}

// PreviewAsset is one sample match of a preview.
type PreviewAsset struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// RulePreview is what a rule would match now, as the caller.
type RulePreview struct {
	// Count is the number of matches; with OverCap it is the cap plus one
	// (the evaluation stops there).
	Count      int            `json:"count"`
	Cap        int            `json:"cap"`
	OverCap    bool           `json:"over_cap"`
	Sample     []PreviewAsset `json:"sample"`
	WouldJoin  int            `json:"would_join"`
	WouldLeave int            `json:"would_leave"`
	Impact     *RuleImpact    `json:"impact,omitempty"`
}

// RuleChange is the result of setting a group's rule.
type RuleChange struct {
	State  *assetgroupdom.RuleState
	Result assetgroupdom.ApplyResult
	Impact RuleImpact
}

// callerUser returns the signed-in person of the request, or a zero ID.
func (s *AssetGroupService) callerUser(ctx context.Context) (shared.ID, datascopeCaller) {
	c := s.dataScope.CallerOf(ctx)
	id, err := shared.IDFromString(c.UserID)
	if err != nil {
		return shared.ID{}, datascopeCaller{IsOwner: c.IsOwner, APIKey: c.APIKey}
	}
	return id, datascopeCaller{IsOwner: c.IsOwner, APIKey: c.APIKey}
}

type datascopeCaller struct{ IsOwner, APIKey bool }

func idPtr(id shared.ID) *shared.ID {
	if id.IsZero() {
		return nil
	}
	return &id
}

// buildRuleFilter compiles the rule into the assets filter, inside scope. The
// rule's filter goes through the same input validation and filter compiler
// as the Assets list.
func (s *AssetGroupService) buildRuleFilter(tenantID shared.ID, rule *assetgroupdom.Rule, scope *shared.DataScope, viewer *shared.ID) (assetdom.Filter, error) {
	f := rule.Filter
	in := ListAssetsInput{
		TenantID: tenantID.String(), Name: f.Name, Types: f.Types, Lenses: f.Lenses,
		Criticalities: f.Criticalities, Statuses: f.Statuses, Scopes: f.Scopes, Exposures: f.Exposures,
		Tags: f.Tags, TagsMode: f.TagsMode, ExcludeTags: f.ExcludeTags, Search: f.Search,
		MinRiskScore: f.MinRiskScore, MaxRiskScore: f.MaxRiskScore, HasFindings: f.HasFindings,
		IsCrownJewel: f.IsCrownJewel, BusinessUnitIDs: f.BusinessUnitIDs, OwnerIDs: f.OwnerIDs,
		InCIDRs: f.InCIDR, HasOwner: f.HasOwner, DataClassifications: f.DataClassifications,
		IsControlPlane: f.IsControlPlane, InternetFacing: f.InternetFacing, Environments: f.Environments,
		Providers: f.Providers, Attribution: f.Attribution, ScopeStatus: f.ScopeStatus,
		Freshness: f.Freshness, Coverage: f.Coverage, TechnologyCategories: f.TechnologyCategories,
	}
	if f.SubType != "" {
		st := f.SubType
		in.SubType = &st
	}
	if len(f.Technology) > 0 {
		in.Technologies = assettech.ParseFilterValues(strings.Join(f.Technology, ","))
	}
	if err := ruleInputValidator().Validate(in); err != nil {
		return assetdom.Filter{}, fmt.Errorf("%w: %s", assetgroupdom.ErrInvalidRule, invalidFieldList(err))
	}
	filter, err := BuildAssetFilter(in)
	if err != nil {
		return assetdom.Filter{}, err
	}
	for _, d := range rule.Domains {
		filter.DomainNames = append(filter.DomainNames, assetdom.DomainName{Name: d.Name, Subdomains: d.Subdomains})
	}
	filter = filter.WithDataScope(scope)
	filter.ProgramTagViewer = viewer
	return filter, nil
}

const matchPage = 1000

// matchSet collects ids once each, in the order they were found, and says when
// there are more than its limit.
type matchSet struct {
	seen  map[shared.ID]struct{}
	ids   []shared.ID
	limit int
}

func newMatchSet(limit int) *matchSet {
	return &matchSet{seen: make(map[shared.ID]struct{}), limit: limit}
}

func (m *matchSet) add(id shared.ID) {
	if _, dup := m.seen[id]; dup {
		return
	}
	m.seen[id] = struct{}{}
	m.ids = append(m.ids, id)
}

func (m *matchSet) over() bool { return len(m.ids) > m.limit }

// result is the ids found, cut at limit+1 when there are more.
func (m *matchSet) result() ([]shared.ID, bool) {
	if m.over() {
		return m.ids[:m.limit+1], true
	}
	return m.ids, false
}

// matchRule returns the ids the rule matches inside scope, in a stable order,
// stopping once there are more than limit (truncated).
func (s *AssetGroupService) matchRule(ctx context.Context, tenantID shared.ID, rule *assetgroupdom.Rule, scope *shared.DataScope, viewer *shared.ID, limit int) ([]shared.ID, bool, error) {
	if s.ruleAssets == nil || s.ruleStore == nil {
		return nil, false, errRulesUnavailable
	}
	base, err := s.buildRuleFilter(tenantID, rule, scope, viewer)
	if err != nil {
		return nil, false, err
	}
	entries := rule.CoveredBy
	if len(entries) == 0 {
		entries = []string{""}
	}
	found := newMatchSet(limit)
	for _, entry := range entries {
		f := base
		if entry != "" {
			id, perr := shared.IDFromString(entry)
			if perr != nil {
				return nil, false, fmt.Errorf("%w: covered_by must list scope entry ids", assetgroupdom.ErrInvalidRule)
			}
			f.CoveredByScopeTarget = &id
		}
		if err := s.collectMatches(ctx, f, found); err != nil {
			return nil, false, err
		}
		if found.over() {
			ids, truncated := found.result()
			return ids, truncated, nil
		}
	}
	if rule.IncludeRelated && len(found.ids) > 0 {
		if err := s.collectRelated(ctx, tenantID, scope, found); err != nil {
			return nil, false, err
		}
	}
	ids, truncated := found.result()
	return ids, truncated, nil
}

// collectMatches pages the ids a filter matches into found, until there are
// more than its limit.
func (s *AssetGroupService) collectMatches(ctx context.Context, f assetdom.Filter, found *matchSet) error {
	after := ""
	for {
		page, err := s.ruleAssets.MatchingIDs(ctx, f, after, matchPage)
		if err != nil {
			return err
		}
		for _, id := range page {
			found.add(id)
		}
		if found.over() || len(page) < matchPage {
			return nil
		}
		after = page[len(page)-1].String()
	}
}

// collectRelated adds the services, URLs and certificates of the matched
// hosts that the editor's data scope allows.
func (s *AssetGroupService) collectRelated(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, found *matchSet) error {
	hosts := slices.Clone(found.ids)
	for i := 0; i < len(hosts); i += 2000 {
		related, err := s.ruleStore.RelatedAssetIDs(ctx, tenantID, hosts[i:min(i+2000, len(hosts))])
		if err != nil {
			return err
		}
		if scope != nil && len(related) > 0 {
			keep, err := s.dataScope.Filter(ctx, scope, related)
			if err != nil {
				return fmt.Errorf("resolve data scope: %w", err)
			}
			for _, id := range related {
				if keep(id) {
					found.add(id)
				}
			}
		} else {
			for _, id := range related {
				found.add(id)
			}
		}
		if found.over() {
			return nil
		}
	}
	return nil
}

func parseRuleInput(raw []byte) (*assetgroupdom.Rule, error) {
	return assetgroupdom.ParseRule(raw)
}

// callerRuleScope resolves what the request's caller sees: their data scope
// and, for a non-owner, the program-tag viewer.
func (s *AssetGroupService) callerRuleScope(ctx context.Context, tenantID shared.ID) (*shared.DataScope, *shared.ID, error) {
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve data scope: %w", err)
	}
	uid, c := s.callerUser(ctx)
	var viewer *shared.ID
	if !uid.IsZero() && !c.IsOwner {
		viewer = &uid
	}
	return scope, viewer, nil
}

func without(ids []shared.ID, drop []shared.ID) []shared.ID {
	if len(drop) == 0 {
		return ids
	}
	skip := make(map[shared.ID]struct{}, len(drop))
	for _, d := range drop {
		skip[d] = struct{}{}
	}
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if _, ok := skip[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}

// impactFor lists what depends on the group and whether wouldJoin widens it.
func (s *AssetGroupService) impactFor(ctx context.Context, tenantID, groupID shared.ID, wouldJoin int) (*RuleImpact, error) {
	teams, err := s.ruleStore.TeamUses(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	scans, err := s.ruleStore.ScanUses(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	imp := &RuleImpact{WouldJoin: wouldJoin, Teams: teams, Scans: scans}
	if imp.Teams == nil {
		imp.Teams = []assetgroupdom.Use{}
	}
	if imp.Scans == nil {
		imp.Scans = []assetgroupdom.Use{}
	}
	if s.guard != nil && len(teams) > 0 {
		flagged, err := s.guard.FlagPrivileged(ctx, tenantID, teams)
		if err != nil {
			return nil, err
		}
		imp.Teams = flagged
		for _, t := range flagged {
			if t.Privileged {
				imp.Privilege = true
			}
		}
	}
	imp.Widens = wouldJoin > 0 && (len(imp.Teams) > 0 || len(imp.Scans) > 0)
	return imp, nil
}

// requireChangeAllowed is the check before any change of a group's members
// or rule: a group that a privileged team's scope rules use is changed only
// by an owner with a recent sign-in.
func (s *AssetGroupService) requireChangeAllowed(ctx context.Context, tenantID, groupID shared.ID) error {
	if s.guard == nil || s.ruleStore == nil {
		return nil
	}
	teams, err := s.ruleStore.TeamUses(ctx, tenantID, groupID)
	if err != nil || len(teams) == 0 {
		return err
	}
	flagged, err := s.guard.FlagPrivileged(ctx, tenantID, teams)
	if err != nil {
		return err
	}
	for _, t := range flagged {
		if t.Privileged {
			return s.guard.RequireOwnerStepUp(ctx, tenantID, s.dataScope.CallerUserID(ctx))
		}
	}
	return nil
}

// PreviewGroupRule evaluates a rule as the caller without saving anything:
// the count, the first matches and, for an existing group, who would join and
// leave and what depends on the group.
func (s *AssetGroupService) PreviewGroupRule(ctx context.Context, tenantIDStr string, groupID *shared.ID, raw []byte) (*RulePreview, error) {
	if s.ruleStore == nil {
		return nil, errRulesUnavailable
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	rule, err := parseRuleInput(raw)
	if err != nil {
		return nil, err
	}
	if groupID != nil {
		if _, _, err := s.writableGroup(ctx, tenantID, *groupID); err != nil {
			return nil, err
		}
	}
	scope, viewer, err := s.callerRuleScope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	limit := s.memberCap()
	ids, truncated, err := s.matchRule(ctx, tenantID, rule, scope, viewer, limit)
	if err != nil {
		return nil, err
	}
	p := &RulePreview{Cap: limit, OverCap: truncated, Sample: []PreviewAsset{}}
	if groupID != nil {
		excluded, err := s.ruleStore.ExcludedIDs(ctx, tenantID, *groupID)
		if err != nil {
			return nil, err
		}
		ids = without(ids, excluded)
	}
	p.Count = len(ids)
	if n := min(len(ids), assetgroupdom.PreviewSampleSize); n > 0 {
		info, err := s.ruleAssets.GetDisplayInfoByIDs(ctx, tenantID, ids[:n])
		if err != nil {
			return nil, err
		}
		for _, id := range ids[:n] {
			if d, ok := info[id]; ok {
				p.Sample = append(p.Sample, PreviewAsset{ID: id.String(), Name: d.Name, Type: string(d.Type)})
			}
		}
	}
	if groupID != nil {
		current, err := s.ruleStore.RuleMemberIDs(ctx, tenantID, *groupID, assetgroupdom.SourceRule)
		if err != nil {
			return nil, err
		}
		// Members the caller cannot see are not theirs to count as leaving.
		visible, err := s.dataScope.FilterForCaller(ctx, tenantID, current)
		if err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
		next := make(map[shared.ID]struct{}, len(ids))
		for _, id := range ids {
			next[id] = struct{}{}
		}
		have := make(map[shared.ID]struct{}, len(current))
		for _, id := range current {
			have[id] = struct{}{}
			if _, ok := next[id]; !ok && visible(id) {
				p.WouldLeave++
			}
		}
		for _, id := range ids {
			if _, ok := have[id]; !ok {
				p.WouldJoin++
			}
		}
		if p.Impact, err = s.impactFor(ctx, tenantID, *groupID, p.WouldJoin); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// GetGroupRule returns the group's rule state as a caller who can see the
// group.
func (s *AssetGroupService) GetGroupRule(ctx context.Context, tenantIDStr string, groupID shared.ID) (*assetgroupdom.RuleState, error) {
	if s.ruleStore == nil {
		return nil, errRulesUnavailable
	}
	if _, err := s.visibleGroup(ctx, tenantIDStr, groupID); err != nil {
		return nil, err
	}
	tenantID, _ := shared.IDFromString(tenantIDStr)
	return s.ruleStore.GetRuleState(ctx, tenantID, groupID)
}

// RuleSummaries returns the rule state of the listed groups that have one.
func (s *AssetGroupService) RuleSummaries(ctx context.Context, tenantIDStr string, groupIDs []shared.ID) map[shared.ID]*assetgroupdom.RuleState {
	if s.ruleStore == nil || len(groupIDs) == 0 {
		return nil
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil
	}
	m, err := s.ruleStore.GetRuleSummaries(ctx, tenantID, groupIDs)
	if err != nil {
		s.logger.Warn("failed to read group rules", "error", err)
		return nil
	}
	return m
}

// ChangeGroupRule sets (or with an empty document clears) the group's rule as
// the caller and evaluates it at once. Widening a group that teams or scans
// use is returned in the impact; the handler audits it.
func (s *AssetGroupService) ChangeGroupRule(ctx context.Context, tenantIDStr string, groupID shared.ID, raw []byte) (*RuleChange, error) {
	if s.ruleStore == nil {
		return nil, errRulesUnavailable
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	if _, _, err := s.writableGroup(ctx, tenantID, groupID); err != nil {
		return nil, err
	}
	if err := s.requireChangeAllowed(ctx, tenantID, groupID); err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		if err := s.ruleStore.SetRule(ctx, tenantID, groupID, nil, nil, nil); err != nil {
			return nil, err
		}
		st, err := s.ruleStore.GetRuleState(ctx, tenantID, groupID)
		return &RuleChange{State: st, Impact: RuleImpact{Teams: []assetgroupdom.Use{}, Scans: []assetgroupdom.Use{}}}, err
	}
	editor, _ := s.callerUser(ctx)
	if editor.IsZero() {
		return nil, errRuleEditor
	}
	rule, err := parseRuleInput(raw)
	if err != nil {
		return nil, err
	}
	// Evaluate before storing, so a rule that cannot run (over the cap, a
	// filter the compiler refuses) is refused with the group unchanged.
	scope, viewer, err := s.callerRuleScope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	ids, truncated, err := s.matchRule(ctx, tenantID, rule, scope, viewer, s.memberCap())
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("%w: the rule matches more than %d assets", assetgroupdom.ErrInvalidRule, s.memberCap())
	}
	// What would join, for the impact summary.
	current, err := s.ruleStore.RuleMemberIDs(ctx, tenantID, groupID, assetgroupdom.SourceRule)
	if err != nil {
		return nil, err
	}
	excluded, err := s.ruleStore.ExcludedIDs(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	have := make(map[shared.ID]struct{}, len(current))
	for _, id := range current {
		have[id] = struct{}{}
	}
	joining := 0
	for _, id := range without(ids, excluded) {
		if _, ok := have[id]; !ok {
			joining++
		}
	}
	impact, err := s.impactFor(ctx, tenantID, groupID, joining)
	if err != nil {
		return nil, err
	}
	if err := s.ruleStore.SetRule(ctx, tenantID, groupID, rule, &editor, &editor); err != nil {
		return nil, err
	}
	res, err := s.ruleStore.ApplyRule(ctx, assetgroupdom.ApplyInput{
		TenantID: tenantID, GroupID: groupID, AssetIDs: ids, Cap: s.memberCap()})
	if err != nil {
		return nil, err
	}
	if res.OverCap {
		_ = s.ruleStore.SetRuleStatus(ctx, tenantID, groupID, assetgroupdom.RuleStatusOverCap)
	}
	s.afterMembershipChange(ctx, tenantID, groupID, res.Joined+res.Left)
	st, err := s.ruleStore.GetRuleState(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	return &RuleChange{State: st, Result: res, Impact: *impact}, nil
}

// afterMembershipChange refreshes the group's counters and the access it
// grants through team scope rules.
func (s *AssetGroupService) afterMembershipChange(ctx context.Context, tenantID, groupID shared.ID, changed int) {
	if changed <= 0 {
		return
	}
	if err := s.repo.RecalculateCounts(ctx, tenantID, groupID); err != nil {
		s.logger.Warn("failed to recalculate group counts", "group_id", groupID.String(), "error", err)
	}
	s.reconcileScopeRules(tenantID, groupID)
}

// EvaluateGroup evaluates a group's rule as its stored editor and writes the
// membership. An editor who left the tenant pauses the rule; a result over
// the cap leaves the members as they are.
func (s *AssetGroupService) EvaluateGroup(ctx context.Context, tenantID, groupID shared.ID) (assetgroupdom.ApplyResult, error) {
	var res assetgroupdom.ApplyResult
	if s.ruleStore == nil {
		return res, errRulesUnavailable
	}
	st, err := s.ruleStore.GetRuleState(ctx, tenantID, groupID)
	if err != nil || st.Rule == nil {
		return res, err
	}
	if st.EditorID == nil {
		return res, s.ruleStore.SetRuleStatus(ctx, tenantID, groupID, assetgroupdom.RuleStatusPaused)
	}
	active, err := s.ruleStore.EditorActive(ctx, tenantID, *st.EditorID)
	if err != nil {
		return res, err
	}
	if !active {
		return res, s.ruleStore.SetRuleStatus(ctx, tenantID, groupID, assetgroupdom.RuleStatusPaused)
	}
	scope, err := s.dataScope.ForUser(ctx, tenantID, *st.EditorID)
	if err != nil {
		return res, fmt.Errorf("resolve editor scope: %w", err)
	}
	var viewer *shared.ID
	if owner, oerr := s.editorIsOwner(ctx, tenantID, *st.EditorID); oerr != nil {
		return res, oerr
	} else if !owner {
		viewer = st.EditorID
	}
	ids, truncated, err := s.matchRule(ctx, tenantID, st.Rule, scope, viewer, s.memberCap())
	if err != nil {
		return res, err
	}
	if truncated {
		res.OverCap = true
		return res, s.ruleStore.SetRuleStatus(ctx, tenantID, groupID, assetgroupdom.RuleStatusOverCap)
	}
	res, err = s.ruleStore.ApplyRule(ctx, assetgroupdom.ApplyInput{
		TenantID: tenantID, GroupID: groupID, AssetIDs: ids, Cap: s.memberCap()})
	if err != nil {
		return res, err
	}
	if res.OverCap {
		return res, s.ruleStore.SetRuleStatus(ctx, tenantID, groupID, assetgroupdom.RuleStatusOverCap)
	}
	s.afterMembershipChange(ctx, tenantID, groupID, res.Joined+res.Left)
	return res, nil
}

func (s *AssetGroupService) editorIsOwner(ctx context.Context, tenantID, editor shared.ID) (bool, error) {
	if s.ownerCheck == nil {
		return false, nil
	}
	return s.ownerCheck(ctx, tenantID, editor)
}

// SetOwnerCheck wires the check whether a user owns the tenant (owners see
// private program assets).
func (s *AssetGroupService) SetOwnerCheck(fn func(ctx context.Context, tenantID, userID shared.ID) (bool, error)) {
	s.ownerCheck = fn
}

// EvaluateTenant evaluates every rule group of the tenant and returns how
// many changed. A tenant of zero ID is every tenant (the periodic recompute).
func (s *AssetGroupService) EvaluateTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	if s.ruleStore == nil {
		return 0, nil
	}
	refs, err := s.ruleStore.ListRuleGroups(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	changed := 0
	var errs []error
	for _, ref := range refs {
		if ctx.Err() != nil {
			return changed, ctx.Err()
		}
		res, err := s.EvaluateGroup(ctx, ref.TenantID, ref.GroupID)
		if err != nil {
			s.logger.Warn("group rule evaluation failed", "group_id", ref.GroupID.String(), "error", err)
			errs = append(errs, err)
			continue
		}
		if res.Joined+res.Left > 0 {
			changed++
		}
	}
	return changed, errors.Join(errs...)
}

// invalidFieldList names the rule fields the validator refused, so the editor
// sees which condition to fix without the validator's own text.
func invalidFieldList(err error) string {
	var ves validator.ValidationErrors
	if !errors.As(err, &ves) || len(ves) == 0 {
		return "a rule condition is not valid"
	}
	names := make([]string, 0, len(ves))
	for _, ve := range ves {
		names = append(names, ve.Field)
	}
	return "not valid: " + strings.Join(names, ", ")
}

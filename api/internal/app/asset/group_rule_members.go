package asset

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/internal/metrics"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	assetgroupdom "github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// reconcileScopeRules re-evaluates the team scope rules that name the group
// (asynchronously: the request does not wait for it).
func (s *AssetGroupService) reconcileScopeRules(tenantID, groupID shared.ID) {
	if s.scopeRuleReconciler == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				metrics.RecordPanic("scope_reconcile")
				s.logger.Error("panic in scope rule reconciliation", "group_id", groupID.String(), "recover", r)
			}
		}()
		s.scopeRuleReconciler(context.Background(), tenantID, groupID)
	}()
}

// PasteLine is one line of a pasted list in the answer.
type PasteLine struct {
	Line  int    `json:"line"`
	Value string `json:"value"`
	Kind  string `json:"kind"`
}

// PasteResult says what a pasted list matched and did.
type PasteResult struct {
	Lines    int `json:"lines"`
	Matched  int `json:"matched"`
	Added    int `json:"added"`
	Created  int `json:"created"`
	Outside  int `json:"candidates"` // created outside the organization's scope
	Skipped  int `json:"skipped"`    // named an asset the caller cannot reach
	NotFound int `json:"not_found"`
	// MissingSample lists the first values with no asset (at most 50).
	MissingSample []PasteLine                   `json:"missing_sample"`
	Rejected      []assetgroupdom.PasteRejected `json:"rejected"`
	Impact        *RuleImpact                   `json:"impact,omitempty"`
}

// PasteOptions tune a paste.
type PasteOptions struct {
	// DryRun matches and reports without changing anything.
	DryRun bool
	// CreateMissing creates the assets the list names that do not exist,
	// through the scope check.
	CreateMissing bool
}

const maxMissingSample = 50

func pasteAssetType(kind string) string {
	switch kind {
	case assetgroupdom.PasteIP:
		return string(assetdom.AssetTypeIPAddress)
	case assetgroupdom.PasteURL:
		return string(assetdom.AssetTypeWebsite)
	default:
		return string(assetdom.AssetTypeDomain)
	}
}

// pasteNames returns the stored names an item can match.
func pasteNames(it assetgroupdom.PasteItem) []string {
	names := []string{it.Value}
	if t, err := assetdom.ParseAssetType(pasteAssetType(it.Kind)); err == nil {
		if n := assetdom.NormalizeName(it.Value, t, ""); n != "" && n != it.Value {
			names = append(names, n)
		}
	}
	return names
}

// PasteToGroup matches a pasted list (names, addresses, ranges, URLs, one
// per line) against the tenant's assets inside the caller's data scope and
// adds what it finds to the group; with CreateMissing it also creates the
// missing names through the scope check (outside the scope they become
// candidates). An asset the caller cannot see counts as missing, so a list
// reveals nothing about it.
func (s *AssetGroupService) PasteToGroup(ctx context.Context, tenantIDStr string, groupID shared.ID, text string, opts PasteOptions) (*PasteResult, error) {
	if s.ruleStore == nil || s.ruleAssets == nil {
		return nil, errRulesUnavailable
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	group, _, err := s.writableGroup(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	items, rejected, err := assetgroupdom.ParsePaste(text)
	if err != nil {
		return nil, err
	}
	res := &PasteResult{Lines: len(items) + len(rejected), Rejected: rejected, MissingSample: []PasteLine{}}
	if res.Rejected == nil {
		res.Rejected = []assetgroupdom.PasteRejected{}
	}
	if !opts.DryRun {
		if err := s.requireChangeAllowed(ctx, tenantID, groupID); err != nil {
			return nil, err
		}
	}

	scope, viewer, err := s.callerRuleScope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	matched, missing, err := s.matchPasteItems(ctx, tenantID, items, scope, viewer, res)
	if err != nil {
		return nil, err
	}

	var created []CreatedPasteAsset
	if opts.CreateMissing && !opts.DryRun && len(missing) > 0 {
		created, err = s.createMissing(ctx, tenantID, missing, res)
		if err != nil {
			return nil, err
		}
		for _, c := range created {
			matched[c.ID] = struct{}{}
		}
		res.NotFound -= res.Created
		if res.NotFound < 0 {
			res.NotFound = 0
		}
	}
	res.Matched = len(matched)
	if opts.DryRun {
		return res, nil
	}

	if group.AssetCount()+len(matched) > s.memberCap() {
		return nil, fmt.Errorf("%w: a group holds at most %d assets", shared.ErrValidation, s.memberCap())
	}
	ids := make([]shared.ID, 0, len(matched))
	for id := range matched {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b shared.ID) int { return strings.Compare(a.String(), b.String()) })
	editor, _ := s.callerUser(ctx)
	added, err := s.ruleStore.AddMembers(ctx, tenantID, groupID, ids, assetgroupdom.SourcePaste, idPtr(editor))
	if err != nil {
		return nil, err
	}
	res.Added = added
	s.afterMembershipChange(ctx, tenantID, groupID, added)
	if res.Impact, err = s.impactFor(ctx, tenantID, groupID, added); err != nil {
		return nil, err
	}
	return res, nil
}

// matchPasteItems matches the items of a pasted list to the tenant's assets by
// name, and ranges to the address assets inside them, keeping only what the
// caller may see: an asset outside their scope is reported missing, like one
// that does not exist. It counts the missing in res and returns the items
// that can be created.
func (s *AssetGroupService) matchPasteItems(ctx context.Context, tenantID shared.ID, items []assetgroupdom.PasteItem, scope *shared.DataScope, viewer *shared.ID, res *PasteResult) (map[shared.ID]struct{}, []assetgroupdom.PasteItem, error) {
	var names []string
	for _, it := range items {
		if it.Kind != assetgroupdom.PasteCIDR {
			names = append(names, pasteNames(it)...)
		}
	}
	byName := make(map[string]shared.ID, len(names))
	for i := 0; i < len(names); i += 1000 {
		m, err := s.ruleAssets.IDsByNames(ctx, tenantID, names[i:min(i+1000, len(names))])
		if err != nil {
			return nil, nil, err
		}
		for k, v := range m {
			byName[k] = v
		}
	}
	candidates := make([]shared.ID, 0, len(byName))
	for _, id := range byName {
		candidates = append(candidates, id)
	}
	visible, err := s.dataScope.FilterForCaller(ctx, tenantID, candidates)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve data scope: %w", err)
	}

	matched := map[shared.ID]struct{}{}
	var missing []assetgroupdom.PasteItem
	for _, it := range items {
		if it.Kind == assetgroupdom.PasteCIDR {
			ids, err := s.matchPasteRange(ctx, tenantID, it, scope, viewer)
			if err != nil {
				return nil, nil, err
			}
			if len(ids) == 0 {
				res.NotFound++
				addMissing(res, it)
			}
			for _, id := range ids {
				matched[id] = struct{}{}
			}
			continue
		}
		found := false
		for _, n := range pasteNames(it) {
			if id, ok := byName[n]; ok && visible(id) {
				matched[id] = struct{}{}
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, it)
			res.NotFound++
			addMissing(res, it)
		}
	}
	return matched, missing, nil
}

// matchPasteRange returns the address assets inside a pasted range that the
// caller may see.
func (s *AssetGroupService) matchPasteRange(ctx context.Context, tenantID shared.ID, it assetgroupdom.PasteItem, scope *shared.DataScope, viewer *shared.ID) ([]shared.ID, error) {
	rule := &assetgroupdom.Rule{Version: assetgroupdom.RuleVersion, Filter: assetgroupdom.RuleFilter{InCIDR: []string{it.Value}}}
	ids, truncated, err := s.matchRule(ctx, tenantID, rule, scope, viewer, s.memberCap())
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("%w: the range %s holds more than %d assets", shared.ErrValidation, it.Value, s.memberCap())
	}
	return ids, nil
}

func addMissing(res *PasteResult, it assetgroupdom.PasteItem) {
	if len(res.MissingSample) < maxMissingSample {
		res.MissingSample = append(res.MissingSample, PasteLine{Line: it.Line, Value: it.Value, Kind: it.Kind})
	}
}

// createMissing creates the missing names of a paste through the scope
// check: the names the organization's scope covers join the inventory; the
// others are held as candidates (out of the inventory, never probed until a
// person decides). An address range is never created.
func (s *AssetGroupService) createMissing(ctx context.Context, tenantID shared.ID, missing []assetgroupdom.PasteItem, res *PasteResult) ([]CreatedPasteAsset, error) {
	if s.paste.Create == nil {
		return nil, fmt.Errorf("%w: creating assets from a list is not available", shared.ErrValidation)
	}
	var todo []assetgroupdom.PasteItem
	for _, it := range missing {
		if it.Kind != assetgroupdom.PasteCIDR {
			todo = append(todo, it)
		}
	}
	if len(todo) > assetgroupdom.MaxPasteCreate {
		return nil, fmt.Errorf("%w: a pasted list creates at most %d assets; %d are missing", shared.ErrValidation, assetgroupdom.MaxPasteCreate, len(todo))
	}
	covered := map[string]bool{}
	if s.paste.Covered != nil {
		hosts := make([]string, 0, len(todo))
		for _, it := range todo {
			hosts = append(hosts, hostOfPasteItem(it))
		}
		m, err := s.paste.Covered(ctx, tenantID, hosts)
		if err != nil {
			// Fail closed: with no answer every created asset is a candidate.
			s.logger.Warn("scope check of a pasted list failed; every created asset is held for review", "error", err)
			m = nil
		}
		covered = m
	}
	editor, _ := s.callerUser(ctx)
	created := make([]CreatedPasteAsset, 0, len(todo))
	var outside []CreatedPasteAsset
	for _, it := range todo {
		a, err := s.paste.Create(ctx, CreateAssetInput{
			TenantID: tenantID.String(), Name: it.Value, Type: pasteAssetType(it.Kind),
			Criticality: "medium", ActorID: idString(editor),
		})
		if err != nil {
			var dup *DuplicateAssetError
			if errors.As(err, &dup) || errors.Is(err, shared.ErrAlreadyExists) {
				// The name exists outside the caller's reach: not theirs.
				res.Skipped++
				continue
			}
			if errors.Is(err, shared.ErrValidation) {
				res.Skipped++
				continue
			}
			return created, err
		}
		c := CreatedPasteAsset{ID: a.ID(), Name: a.Name(), Type: assetdom.TypeRef{Type: a.Type(), SubType: a.SubType()}}
		created = append(created, c)
		if !covered[hostOfPasteItem(it)] {
			outside = append(outside, c)
		}
	}
	res.Created = len(created)
	res.Outside = len(outside)
	if len(outside) > 0 {
		if s.paste.HoldCandidates == nil {
			return created, fmt.Errorf("created assets outside the scope could not be held for review")
		}
		if err := s.paste.HoldCandidates(ctx, tenantID, outside); err != nil {
			return created, fmt.Errorf("created assets outside the scope could not be held for review: %w", err)
		}
	}
	return created, nil
}

func idString(id shared.ID) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}

// hostOfPasteItem is the host the scope check sees for an item.
func hostOfPasteItem(it assetgroupdom.PasteItem) string {
	if it.Kind != assetgroupdom.PasteURL {
		return it.Value
	}
	return assetdom.HostOf(it.Value)
}

// AddMatchingToGroup adds every asset a filter matches inside the caller's
// data scope to the group as manual members ("add all N matching": not
// limited to the page the caller sees). The filter is a rule document.
func (s *AssetGroupService) AddMatchingToGroup(ctx context.Context, tenantIDStr string, groupID shared.ID, raw []byte) (added, matched int, impact *RuleImpact, err error) {
	if s.ruleStore == nil {
		return 0, 0, nil, errRulesUnavailable
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	group, _, err := s.writableGroup(ctx, tenantID, groupID)
	if err != nil {
		return 0, 0, nil, err
	}
	rule, err := parseRuleInput(raw)
	if err != nil {
		return 0, 0, nil, err
	}
	if err := s.requireChangeAllowed(ctx, tenantID, groupID); err != nil {
		return 0, 0, nil, err
	}
	scope, viewer, err := s.callerRuleScope(ctx, tenantID)
	if err != nil {
		return 0, 0, nil, err
	}
	ids, truncated, err := s.matchRule(ctx, tenantID, rule, scope, viewer, s.memberCap())
	if err != nil {
		return 0, 0, nil, err
	}
	if truncated || group.AssetCount()+len(ids) > s.memberCap() {
		return 0, 0, nil, fmt.Errorf("%w: a group holds at most %d assets", shared.ErrValidation, s.memberCap())
	}
	editor, _ := s.callerUser(ctx)
	added, err = s.ruleStore.AddMembers(ctx, tenantID, groupID, ids, assetgroupdom.SourceManual, idPtr(editor))
	if err != nil {
		return 0, 0, nil, err
	}
	s.afterMembershipChange(ctx, tenantID, groupID, added)
	impact, err = s.impactFor(ctx, tenantID, groupID, added)
	return added, len(ids), impact, err
}

// ListGroupHistory pages who joined and left a group the caller can see. A
// restricted caller sees only the entries of assets in their scope.
func (s *AssetGroupService) ListGroupHistory(ctx context.Context, tenantIDStr string, groupID shared.ID, pageNum, perPage int) (pagination.Result[*assetgroupdom.HistoryEntry], error) {
	empty := pagination.Result[*assetgroupdom.HistoryEntry]{}
	if s.ruleStore == nil {
		return empty, errRulesUnavailable
	}
	scope, err := s.visibleGroup(ctx, tenantIDStr, groupID)
	if err != nil {
		return empty, err
	}
	tenantID, _ := shared.IDFromString(tenantIDStr)
	res, err := s.ruleStore.ListHistory(ctx, tenantID, groupID, pagination.New(pageNum, perPage))
	if err != nil {
		return empty, err
	}
	return s.scopeHistory(ctx, tenantID, scope, res)
}

// ListAssetGroupHistory pages the groups an asset joined and left, for an
// asset the caller can see (404 otherwise).
func (s *AssetGroupService) ListAssetGroupHistory(ctx context.Context, tenantIDStr string, assetID shared.ID, pageNum, perPage int) (pagination.Result[*assetgroupdom.HistoryEntry], error) {
	empty := pagination.Result[*assetgroupdom.HistoryEntry]{}
	if s.ruleStore == nil {
		return empty, errRulesUnavailable
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return empty, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	own, err := s.repo.FilterTenantAssetIDs(ctx, tenantID, []shared.ID{assetID})
	if err != nil {
		return empty, err
	}
	if len(own) == 0 {
		return empty, shared.ErrNotFound
	}
	if err := s.dataScope.AssertAsset(ctx, tenantID, assetID); err != nil {
		return empty, err
	}
	return s.ruleStore.ListAssetHistory(ctx, tenantID, assetID, pagination.New(pageNum, perPage))
}

func (s *AssetGroupService) scopeHistory(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, res pagination.Result[*assetgroupdom.HistoryEntry]) (pagination.Result[*assetgroupdom.HistoryEntry], error) {
	if !scope.Restricted() || len(res.Data) == 0 {
		return res, nil
	}
	ids := make([]shared.ID, len(res.Data))
	for i, e := range res.Data {
		ids[i] = e.AssetID
	}
	keep, err := s.dataScope.FilterForCaller(ctx, tenantID, ids)
	if err != nil {
		return res, fmt.Errorf("resolve data scope: %w", err)
	}
	kept := res.Data[:0]
	for _, e := range res.Data {
		if keep(e.AssetID) {
			kept = append(kept, e)
		}
	}
	res.Data = kept
	return res, nil
}

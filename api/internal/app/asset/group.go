package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/metrics"

	assetgroupdom "github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AssetGroupService handles asset group business logic.
type AssetGroupService struct {
	repo   assetgroupdom.Repository
	logger *logger.Logger

	// Scope rule reconciler callback (set by services.go wiring)
	scopeRuleReconciler scope.RuleGroupReconcilerFunc

	// Layer 2 data scope for group contents (nil = unrestricted).
	dataScope *datascope.Enforcer

	// Smart groups (group_rule.go); all nil in a service without rules.
	ruleStore   assetgroupdom.RuleStore
	ruleAssets  RuleAssetSource
	guard       GroupAccessGuard
	paste       PasteAssets
	ownerCheck  func(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	capOverride int
}

// SetDataScope wires the Layer 2 data-scope enforcer: a restricted member
// sees only the in-scope assets and findings of a group.
func (s *AssetGroupService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// NewAssetGroupService creates a new asset group service.
func NewAssetGroupService(repo assetgroupdom.Repository, log *logger.Logger) *AssetGroupService {
	return &AssetGroupService{
		repo:   repo,
		logger: log,
	}
}

// SetScopeRuleReconciler sets the scope rule reconciler callback.
// Called when asset group membership changes to re-evaluate scope rules.
func (s *AssetGroupService) SetScopeRuleReconciler(fn scope.RuleGroupReconcilerFunc) {
	s.scopeRuleReconciler = fn
}

// CreateAssetGroupInput represents input for creating an asset group.
type CreateAssetGroupInput struct {
	TenantID     string
	Name         string   `validate:"required,min=1,max=255"`
	Description  string   `validate:"max=1000"`
	Environment  string   `validate:"required,asset_group_environment"`
	Criticality  string   `validate:"required,asset_group_criticality"`
	BusinessUnit string   `validate:"max=255"`
	Owner        string   `validate:"max=255"`
	OwnerEmail   string   `validate:"omitempty,email,max=255"`
	Tags         []string `validate:"max=20,dive,max=50"`
	AssetIDs     []string `validate:"max=1000,dive,uuid"`
	// Rule is an optional group rule document (assetgroupdom.Rule): the
	// group then fills itself.
	Rule json.RawMessage
}

// UpdateAssetGroupInput represents input for updating an asset group.
type UpdateAssetGroupInput struct {
	Name         *string `validate:"omitempty,min=1,max=255"`
	Description  *string `validate:"omitempty,max=1000"`
	Environment  *string `validate:"omitempty,asset_group_environment"`
	Criticality  *string `validate:"omitempty,asset_group_criticality"`
	BusinessUnit *string `validate:"omitempty,max=255"`
	Owner        *string `validate:"omitempty,max=255"`
	// Email format is checked in UpdateAssetGroup only when non-empty; an empty
	// string is an explicit "clear the owner email" and must be allowed through.
	OwnerEmail *string  `validate:"omitempty,max=255"`
	Tags       []string `validate:"omitempty,max=20,dive,max=50"`
}

// ListAssetGroupsInput represents input for listing asset groups.
type ListAssetGroupsInput struct {
	TenantID       string
	Search         string
	Environments   []string
	Criticalities  []string
	BusinessUnit   string
	BusinessUnitID string
	Owner          string
	Tags           []string
	HasFindings    *bool
	MinRiskScore   *int
	MaxRiskScore   *int
	Sort           string
	Page           int `validate:"min=1"`
	PerPage        int `validate:"min=1,max=100"`
}

// ListAssetGroupsOutput represents output from listing asset groups.
type ListAssetGroupsOutput struct {
	Groups []*assetgroupdom.AssetGroup
	Total  int64
	Page   int
	Pages  int
}

// CreateAssetGroup creates a new asset group.
func (s *AssetGroupService) CreateAssetGroup(ctx context.Context, input CreateAssetGroupInput) (*assetgroupdom.AssetGroup, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	env, ok := assetgroupdom.ParseEnvironment(input.Environment)
	if !ok {
		return nil, fmt.Errorf("%w: invalid environment", shared.ErrValidation)
	}

	crit, ok := assetgroupdom.ParseCriticality(input.Criticality)
	if !ok {
		return nil, fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
	}

	// A rule is checked before the group exists, so a refused rule never
	// leaves a group behind.
	hasRule := len(strings.TrimSpace(string(input.Rule))) > 0 && strings.TrimSpace(string(input.Rule)) != "null"
	if hasRule {
		if s.ruleStore == nil {
			return nil, errRulesUnavailable
		}
		if _, err := parseRuleInput(input.Rule); err != nil {
			return nil, err
		}
	}

	// Check for duplicate name
	exists, err := s.repo.ExistsByName(ctx, tenantID, input.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: asset group with this name already exists", shared.ErrAlreadyExists)
	}

	group, err := assetgroupdom.NewAssetGroupWithTenant(tenantID, input.Name, env, crit)
	if err != nil {
		return nil, err
	}

	group.UpdateDescription(input.Description)
	group.UpdateBusinessUnit(input.BusinessUnit)
	group.UpdateOwner(input.Owner, input.OwnerEmail)
	if len(input.Tags) > 0 {
		group.SetTags(input.Tags)
	}

	// Members are checked before the group exists, so a refused id never
	// leaves a half-created group behind.
	assetIDs, err := s.memberAssetIDs(ctx, tenantID, input.AssetIDs)
	if err != nil {
		return nil, err
	}

	if err := s.repo.Create(ctx, group); err != nil {
		return nil, err
	}

	if len(assetIDs) > 0 {
		if _, err := s.repo.AddAssets(ctx, group.ID(), assetIDs); err != nil {
			s.logger.Error("failed to add assets to group", "group_id", group.ID(), "error", err)
		}
		// Recalculate counts
		if err := s.repo.RecalculateCounts(ctx, group.ID()); err != nil {
			s.logger.Error("failed to recalculate counts", "group_id", group.ID(), "error", err)
		}
		// Refresh group from database
		if refreshed, err := s.repo.GetByTenantAndID(ctx, tenantID, group.ID()); err == nil && refreshed != nil {
			group = refreshed
		}
	}

	if hasRule {
		if _, err := s.ChangeGroupRule(ctx, input.TenantID, group.ID(), input.Rule); err != nil {
			// The group was made for this rule: do not leave it empty.
			if derr := s.repo.Delete(ctx, tenantID, group.ID()); derr != nil {
				s.logger.Error("failed to remove a group whose rule was refused", "id", group.ID(), "error", derr)
			}
			return nil, err
		}
		if refreshed, err := s.repo.GetByTenantAndID(ctx, tenantID, group.ID()); err == nil && refreshed != nil {
			group = refreshed
		}
	}

	s.logger.Info("asset group created", "id", group.ID(), "name", logger.SanitizeValue(input.Name))
	view, err := s.readerView(ctx, tenantID, group)
	if errors.Is(err, shared.ErrNotFound) {
		// A restricted creator's group with none of their assets is not
		// visible to them yet; they still get what they just wrote, less
		// the owner email no restricted caller is shown.
		group.HideOwnerEmail()
		return group, nil
	}
	return view, err
}

// GetAssetGroup retrieves an asset group by tenant and ID, as the caller
// sees it: for a restricted reader the counts, risk and findings cover only
// the members in their data scope (L-18).
func (s *AssetGroupService) GetAssetGroup(ctx context.Context, tenantIDStr string, id shared.ID) (*assetgroupdom.AssetGroup, error) {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	group, err := s.repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return s.readerView(ctx, tenantID, group)
}

// readerView returns group as the caller may see it. An unrestricted caller
// gets the stored row; a restricted one gets the group re-read with the
// counts computed over the members in their data scope and without the
// owner email, or shared.ErrNotFound when the group is not visible to them
// (research/233 D4: none of its members is in their scope and no scope rule
// of their teams names it). Every handler response that carries a group
// goes through it.
func (s *AssetGroupService) readerView(ctx context.Context, tenantID shared.ID, group *assetgroupdom.AssetGroup) (*assetgroupdom.AssetGroup, error) {
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	return s.viewAs(ctx, tenantID, group, scope)
}

// viewAs is readerView for a resolved scope.
func (s *AssetGroupService) viewAs(ctx context.Context, tenantID shared.ID, group *assetgroupdom.AssetGroup, scope *shared.DataScope) (*assetgroupdom.AssetGroup, error) {
	if scope == nil {
		return group, nil
	}
	filter := assetgroupdom.NewFilter().WithTenantID(tenantID.String())
	filter.IDs = []shared.ID{group.ID()}
	filter.DataScope = scope
	res, err := s.repo.List(ctx, filter, assetgroupdom.NewListOptions(), pagination.New(1, 1))
	if err != nil {
		return nil, err
	}
	if len(res.Data) == 0 {
		return nil, shared.ErrNotFound
	}
	view := res.Data[0]
	if scope.Restricted() {
		view.HideOwnerEmail()
	}
	return view, nil
}

// visibleGroup returns the caller's scope when they may see the group of
// the tenant, and shared.ErrNotFound otherwise (another tenant's, unknown, or not
// visible to a restricted caller): the read paths of one group (its
// members, its findings) answer 404 for a group the caller cannot see.
func (s *AssetGroupService) visibleGroup(ctx context.Context, tenantIDStr string, groupID shared.ID) (*shared.DataScope, error) {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	group, err := s.repo.GetByTenantAndID(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if scope.Restricted() {
		if _, err := s.viewAs(ctx, tenantID, group, scope); err != nil {
			return nil, err
		}
	}
	return scope, nil
}

// writableGroup loads the group of the tenant for a change by the caller. A
// restricted caller may change a group visible to them, or an empty one (a
// group they just created holds none of their assets yet); any other group
// answers shared.ErrNotFound, as a read does. It also reports whether the
// caller is restricted, so an update keeps the owner email they cannot see.
func (s *AssetGroupService) writableGroup(ctx context.Context, tenantID, groupID shared.ID) (*assetgroupdom.AssetGroup, bool, error) {
	group, err := s.repo.GetByTenantAndID(ctx, tenantID, groupID)
	if err != nil {
		return nil, false, err
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, false, fmt.Errorf("resolve data scope: %w", err)
	}
	if !scope.Restricted() {
		return group, false, nil
	}
	if _, err := s.viewAs(ctx, tenantID, group, scope); err == nil {
		return group, true, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, true, err
	}
	members, err := s.repo.GetGroupAssets(ctx, groupID, pagination.New(1, 1), nil)
	if err != nil {
		return nil, true, err
	}
	if members.Total > 0 {
		return nil, true, shared.ErrNotFound
	}
	return group, true, nil
}

// UpdateAssetGroup updates an existing asset group.
func (s *AssetGroupService) UpdateAssetGroup(ctx context.Context, tenantIDStr string, id shared.ID, input UpdateAssetGroupInput) (*assetgroupdom.AssetGroup, error) {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	group, restricted, err := s.writableGroup(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if restricted {
		// The owner email is hidden from a restricted caller, so their
		// edit form never holds it: keep the stored value.
		input.OwnerEmail = nil
	}

	if input.Name != nil {
		if err := group.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		group.UpdateDescription(*input.Description)
	}

	if input.Environment != nil {
		env, ok := assetgroupdom.ParseEnvironment(*input.Environment)
		if !ok {
			return nil, fmt.Errorf("%w: invalid environment", shared.ErrValidation)
		}
		if err := group.UpdateEnvironment(env); err != nil {
			return nil, err
		}
	}

	if input.Criticality != nil {
		crit, ok := assetgroupdom.ParseCriticality(*input.Criticality)
		if !ok {
			return nil, fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
		}
		if err := group.UpdateCriticality(crit); err != nil {
			return nil, err
		}
	}

	if input.BusinessUnit != nil {
		group.UpdateBusinessUnit(*input.BusinessUnit)
	}

	if input.Owner != nil || input.OwnerEmail != nil {
		owner := group.Owner()
		email := group.OwnerEmail()
		if input.Owner != nil {
			owner = *input.Owner
		}
		if input.OwnerEmail != nil {
			// An explicit empty string clears the owner email. Only validate the
			// address format when a non-empty value is supplied — the handler no
			// longer runs the `email` struct-tag rule because `omitempty` does not
			// skip a non-nil *string pointing at "" (it rejected legitimate clears).
			if e := strings.TrimSpace(*input.OwnerEmail); e != "" {
				if _, err := mail.ParseAddress(e); err != nil {
					return nil, fmt.Errorf("%w: invalid owner email", shared.ErrValidation)
				}
			}
			email = *input.OwnerEmail
		}
		group.UpdateOwner(owner, email)
	}

	if input.Tags != nil {
		group.SetTags(input.Tags)
	}

	if err := s.repo.Update(ctx, tenantID, group); err != nil {
		return nil, err
	}

	s.logger.Info("asset group updated", "id", id)
	view, err := s.readerView(ctx, tenantID, group)
	if errors.Is(err, shared.ErrNotFound) {
		// An empty group a restricted caller may change but not see.
		group.HideOwnerEmail()
		return group, nil
	}
	return view, err
}

// DeleteAssetGroup deletes an asset group within the given tenant scope.
// Security: tenantID required so the SQL DELETE is tenant-scoped (S-1 audit).
func (s *AssetGroupService) DeleteAssetGroup(ctx context.Context, tenantIDStr string, id shared.ID) error {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	if _, _, err := s.writableGroup(ctx, tenantID, id); err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	s.logger.Info("asset group deleted", "id", id, "tenant_id", tenantIDStr)
	return nil
}

// ListAssetGroups lists asset groups with filtering and pagination.
func (s *AssetGroupService) ListAssetGroups(ctx context.Context, input ListAssetGroupsInput) (*ListAssetGroupsOutput, error) {
	filter := assetgroupdom.NewFilter().WithTenantID(input.TenantID)

	if input.Search != "" {
		filter = filter.WithSearch(input.Search)
	}

	if len(input.Environments) > 0 {
		envs := make([]assetgroupdom.Environment, 0, len(input.Environments))
		for _, e := range input.Environments {
			if env, ok := assetgroupdom.ParseEnvironment(e); ok {
				envs = append(envs, env)
			}
		}
		if len(envs) > 0 {
			filter = filter.WithEnvironments(envs...)
		}
	}

	if len(input.Criticalities) > 0 {
		crits := make([]assetgroupdom.Criticality, 0, len(input.Criticalities))
		for _, c := range input.Criticalities {
			if crit, ok := assetgroupdom.ParseCriticality(c); ok {
				crits = append(crits, crit)
			}
		}
		if len(crits) > 0 {
			filter = filter.WithCriticalities(crits...)
		}
	}

	if input.BusinessUnit != "" {
		filter = filter.WithBusinessUnit(input.BusinessUnit)
	}

	if input.BusinessUnitID != "" {
		filter = filter.WithBusinessUnitID(input.BusinessUnitID)
	}

	if len(input.Tags) > 0 {
		filter = filter.WithTags(input.Tags...)
	}

	if input.HasFindings != nil {
		filter = filter.WithHasFindings(*input.HasFindings)
	}

	if input.MinRiskScore != nil {
		filter.MinRiskScore = input.MinRiskScore
	}
	if input.MaxRiskScore != nil {
		filter.MaxRiskScore = input.MaxRiskScore
	}

	opts := assetgroupdom.NewListOptions()
	if input.Sort != "" {
		sortOpt := pagination.NewSortOption(assetgroupdom.AllowedSortFields()).Parse(input.Sort)
		opts = opts.WithSort(sortOpt)
	}

	page := pagination.New(input.Page, input.PerPage)

	// A restricted reader lists only the groups visible to them, and their
	// counts, risk, findings (and the filters and sorts on them) cover only
	// the members in their data scope (L-18).
	if tid, err := shared.IDFromString(input.TenantID); err == nil {
		scope, err := s.dataScope.Resolve(ctx, tid)
		if err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
		filter.DataScope = scope
	}

	result, err := s.repo.List(ctx, filter, opts, page)
	if err != nil {
		return nil, err
	}
	if filter.DataScope.Restricted() {
		for _, g := range result.Data {
			g.HideOwnerEmail()
		}
	}

	return &ListAssetGroupsOutput{
		Groups: result.Data,
		Total:  result.Total,
		Page:   result.Page,
		Pages:  result.TotalPages,
	}, nil
}

// GetAssetGroupStats retrieves aggregated statistics.
func (s *AssetGroupService) GetAssetGroupStats(ctx context.Context, tenantID string) (*assetgroupdom.Stats, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	scope, err := s.dataScope.Resolve(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	return s.repo.GetStats(ctx, tid, scope)
}

// errAssetsNotFound is the one answer for any member id the caller may not
// add: unknown, another tenant's, or outside the caller's data scope. The
// three are indistinguishable, so the response confirms nothing about ids
// the caller cannot see.
var errAssetsNotFound = fmt.Errorf("%w: one or more assets do not exist", shared.ErrValidation)

// parseAssetIDs parses and de-duplicates asset id strings, dropping
// unparseable ones (the handlers already reject those).
func parseAssetIDs(raw []string) []shared.ID {
	seen := make(map[shared.ID]struct{}, len(raw))
	ids := make([]shared.ID, 0, len(raw))
	for _, idStr := range raw {
		id, err := shared.IDFromString(idStr)
		if err != nil || id.IsZero() {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

// memberAssetIDs parses the asset ids a caller asks to add to a group and
// refuses the whole request unless every one is an asset of tenantID inside
// the caller's data scope.
func (s *AssetGroupService) memberAssetIDs(ctx context.Context, tenantID shared.ID, raw []string) ([]shared.ID, error) {
	ids := parseAssetIDs(raw)
	if len(ids) == 0 {
		return nil, nil
	}
	own, err := s.repo.FilterTenantAssetIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	if len(own) != len(ids) {
		return nil, errAssetsNotFound
	}
	inScope, err := s.dataScope.FilterForCaller(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	for _, id := range ids {
		if !inScope(id) {
			return nil, errAssetsNotFound
		}
	}
	return ids, nil
}

// verifyGroupTenant ensures the group belongs to the given tenant, and that
// a restricted caller may change it (writableGroup), before any membership
// change. The asset_group_members queries are keyed only by group_id (the
// join table has no tenant_id), so without this guard a caller could mutate
// another tenant's group by supplying its UUID (IDOR). Returns
// shared.ErrNotFound (→ 404) otherwise.
func (s *AssetGroupService) verifyGroupTenant(ctx context.Context, tenantIDStr string, groupID shared.ID) error {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	_, _, err = s.writableGroup(ctx, tenantID, groupID)
	return err
}

// AddAssetsToGroup adds assets to a group.
func (s *AssetGroupService) AddAssetsToGroup(ctx context.Context, tenantID string, groupID shared.ID, assetIDs []string) error {
	if err := s.verifyGroupTenant(ctx, tenantID, groupID); err != nil {
		return err
	}
	tid, _ := shared.IDFromString(tenantID) // validated by verifyGroupTenant

	ids, err := s.memberAssetIDs(ctx, tid, assetIDs)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if err := s.requireChangeAllowed(ctx, tid, groupID); err != nil {
		return err
	}

	if s.ruleStore != nil {
		editor, _ := s.callerUser(ctx)
		if _, err := s.ruleStore.AddMembers(ctx, tid, groupID, ids, assetgroupdom.SourceManual, idPtr(editor)); err != nil {
			return err
		}
	} else {
		matched, err := s.repo.AddAssets(ctx, groupID, ids)
		if err != nil {
			return err
		}
		if matched != len(ids) {
			// The repository admits only the group's tenant; a mismatch here
			// means an asset moved or vanished since the check above.
			return errAssetsNotFound
		}
	}

	// Recalculate counts
	if err := s.repo.RecalculateCounts(ctx, groupID); err != nil {
		return err
	}

	// Trigger scope rule reconciliation for asset group membership change (async)
	if s.scopeRuleReconciler != nil {
		gid := groupID
		go func() {
			defer func() {
				if r := recover(); r != nil {
					metrics.RecordPanic("scope_reconcile")
					s.logger.Error("panic in scope rule reconciliation", "group_id", gid.String(), "recover", r)
				}
			}()
			s.scopeRuleReconciler(context.Background(), tid, gid)
		}()
	}

	return nil
}

// RemoveAssetsFromGroup removes assets from a group.
func (s *AssetGroupService) RemoveAssetsFromGroup(ctx context.Context, tenantID string, groupID shared.ID, assetIDs []string) error {
	if err := s.verifyGroupTenant(ctx, tenantID, groupID); err != nil {
		return err
	}

	tid, _ := shared.IDFromString(tenantID) // validated by verifyGroupTenant

	// A scoped member removes only the members they can see; out-of-scope
	// ids are skipped exactly like ids that are not members.
	ids := parseAssetIDs(assetIDs)
	inScope, err := s.dataScope.FilterForCaller(ctx, tid, ids)
	if err != nil {
		return fmt.Errorf("resolve data scope: %w", err)
	}
	kept := ids[:0]
	for _, id := range ids {
		if inScope(id) {
			kept = append(kept, id)
		}
	}
	ids = kept

	if len(ids) == 0 {
		return nil
	}
	if err := s.requireChangeAllowed(ctx, tid, groupID); err != nil {
		return err
	}

	if s.ruleStore != nil {
		// In a group that has a rule, taking an asset out keeps it out: the
		// rule would bring it back otherwise.
		st, err := s.ruleStore.GetRuleState(ctx, tid, groupID)
		if err != nil {
			return err
		}
		editor, _ := s.callerUser(ctx)
		if _, err := s.ruleStore.RemoveMembers(ctx, tid, groupID, ids, st.Rule != nil, idPtr(editor)); err != nil {
			return err
		}
	} else if err := s.repo.RemoveAssets(ctx, groupID, ids); err != nil {
		return err
	}

	// Recalculate counts
	if err := s.repo.RecalculateCounts(ctx, groupID); err != nil {
		return err
	}

	// Trigger scope rule reconciliation for asset group membership change (async)
	if s.scopeRuleReconciler != nil {
		gid := groupID
		go func() {
			defer func() {
				if r := recover(); r != nil {
					metrics.RecordPanic("scope_reconcile")
					s.logger.Error("panic in scope rule reconciliation", "group_id", gid.String(), "recover", r)
				}
			}()
			s.scopeRuleReconciler(context.Background(), tid, gid)
		}()
	}

	return nil
}

// GetGroupAssets retrieves assets in a group.
func (s *AssetGroupService) GetGroupAssets(ctx context.Context, tenantID string, groupID shared.ID, pageNum, perPage int) (pagination.Result[*assetgroupdom.GroupAsset], error) {
	// A group the caller cannot see answers 404, not an empty page.
	scope, err := s.visibleGroup(ctx, tenantID, groupID)
	if err != nil {
		return pagination.Result[*assetgroupdom.GroupAsset]{}, err
	}
	page := pagination.New(pageNum, perPage)
	return s.repo.GetGroupAssets(ctx, groupID, page, scope)
}

// GetGroupFindings retrieves findings for assets in a group.
func (s *AssetGroupService) GetGroupFindings(ctx context.Context, tenantID string, groupID shared.ID, pageNum, perPage int) (pagination.Result[*assetgroupdom.GroupFinding], error) {
	// A group the caller cannot see answers 404, not an empty page.
	scope, err := s.visibleGroup(ctx, tenantID, groupID)
	if err != nil {
		return pagination.Result[*assetgroupdom.GroupFinding]{}, err
	}
	page := pagination.New(pageNum, perPage)
	return s.repo.GetGroupFindings(ctx, groupID, page, scope)
}

// BulkUpdateInput represents input for bulk updating asset groups.
type BulkUpdateInput struct {
	GroupIDs    []string
	Environment *string `validate:"omitempty,asset_group_environment"`
	Criticality *string `validate:"omitempty,asset_group_criticality"`
}

// BulkUpdateAssetGroups updates multiple asset groups.
func (s *AssetGroupService) BulkUpdateAssetGroups(ctx context.Context, tenantID string, input BulkUpdateInput) *BulkGroupResult {
	res := &BulkGroupResult{}
	for _, idStr := range input.GroupIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			res.fail(idStr, "invalid group ID")
			continue
		}

		_, err = s.UpdateAssetGroup(ctx, tenantID, id, UpdateAssetGroupInput{
			Environment: input.Environment,
			Criticality: input.Criticality,
		})
		if err != nil {
			s.logger.Warn("bulk update failed for group", "id", idStr, "error", err)
			res.fail(idStr, err.Error())
			continue
		}
		res.Succeeded++
	}
	return res
}

// BulkDeleteAssetGroups deletes multiple asset groups.
func (s *AssetGroupService) BulkDeleteAssetGroups(ctx context.Context, tenantIDStr string, groupIDs []string) *BulkGroupResult {
	res := &BulkGroupResult{}
	for _, idStr := range groupIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			res.fail(idStr, "invalid group ID")
			continue
		}

		if err := s.DeleteAssetGroup(ctx, tenantIDStr, id); err != nil {
			s.logger.Warn("bulk delete failed for group", "id", idStr, "error", err)
			res.fail(idStr, err.Error())
			continue
		}
		res.Succeeded++
	}
	return res
}

// BulkGroupResult reports the outcome of a best-effort bulk asset-group
// operation: how many items succeeded/failed and a per-item error for each
// failure, so callers can tell which IDs failed and why (rather than only a
// success count).
type BulkGroupResult struct {
	Succeeded int      `json:"succeeded"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}

func (r *BulkGroupResult) fail(id, msg string) {
	r.Failed++
	r.Errors = append(r.Errors, fmt.Sprintf("%s: %s", id, msg))
}

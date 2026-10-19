package attack

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// SurfaceStats represents aggregated attack surface statistics.
type SurfaceStats struct {
	// Summary stats
	TotalAssets int `json:"total_assets"`
	// InternetFacingAssets: assets that are internet-facing
	// (asset.InternetFacing). A population, not a problem count.
	InternetFacingAssets int `json:"internet_facing_assets"`
	// CriticalInternetFacingAssets: the same, limited to critical/high
	// criticality.
	CriticalInternetFacingAssets int     `json:"critical_internet_facing_assets"`
	RiskScore                    float64 `json:"risk_score"`

	// Trends over the last 7 days (TrendWindowDays), counts never negative:
	//   - total_assets_change: assets added to the inventory;
	//   - newly_exposed: "became internet-facing" changes, counted exactly
	//     like Assets > What changed (asset.NewlyExposedHistory), so both
	//     pages show the same number.
	TotalAssetsChange int `json:"total_assets_change"`
	NewlyExposed      int `json:"newly_exposed"`
	TrendWindowDays   int `json:"trend_window_days"`

	// Asset breakdown by type with exposed count
	AssetBreakdown []AssetTypeBreakdown `json:"asset_breakdown"`

	// Top exposed services
	ExposedServicesList []ExposedService `json:"exposed_services_list"`

	// Recent changes
	RecentChanges []AssetChange `json:"recent_changes"`
}

// AssetTypeBreakdown represents asset count breakdown by type.
type AssetTypeBreakdown struct {
	Type    string `json:"type"`
	Total   int    `json:"total"`
	Exposed int    `json:"exposed"`
}

// ExposedService represents an exposed service/asset.
type ExposedService struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Port         int       `json:"port,omitempty"`
	Exposure     string    `json:"exposure"`
	Criticality  string    `json:"criticality"`
	FindingCount int       `json:"finding_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// AssetChange represents a recent asset change.
type AssetChange struct {
	Type      string    `json:"type"` // added, removed, changed
	AssetID   string    `json:"asset_id,omitempty"`
	AssetName string    `json:"asset_name"`
	AssetType string    `json:"asset_type"`
	Timestamp time.Time `json:"timestamp"`
	// AttributionState is the asset's recorded attribution ("" = no record,
	// a legacy confirmed asset), and InInventory whether that puts it in the
	// inventory (RFC-054 §4.4): a name the scan found that waits for review
	// is listed as "added" with needs_review and in_inventory false.
	AttributionState string `json:"attribution_state,omitempty"`
	InInventory      bool   `json:"in_inventory"`
}

// AttributionRecords reads the stored attribution of assets
// (*postgres.AttributionRepository). Tenant-scoped.
type AttributionRecords interface {
	Records(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.Record, error)
}

// SetAttributionRecords annotates recent changes with each asset's
// attribution state. Optional: without it every change says in_inventory.
func (s *SurfaceService) SetAttributionRecords(r AttributionRecords) {
	s.attribution = r
}

// SurfaceRepository defines the interface for attack surface data access.
type SurfaceRepository interface {
	// GetStats returns attack surface statistics for a tenant
	GetStats(ctx context.Context, tenantID shared.ID) (*SurfaceStatsData, error)
	// GetExposedServices returns top exposed services/assets
	GetExposedServices(ctx context.Context, tenantID shared.ID, limit int) ([]ExposedService, error)
	// GetRecentChanges returns recent asset changes
	GetRecentChanges(ctx context.Context, tenantID shared.ID, limit int) ([]AssetChange, error)
	// GetStatsWithTrends returns stats with week-over-week comparison
	GetStatsWithTrends(ctx context.Context, tenantID shared.ID) (*SurfaceStatsData, error)
}

// SurfaceStatsData holds raw attack surface statistics.
type SurfaceStatsData struct {
	TotalAssets             int
	ExposedServices         int
	CriticalExposures       int
	AverageRiskScore        float64
	TotalAssetsChange       int
	ExposedServicesChange   int
	CriticalExposuresChange int
	ByType                  map[string]int
	ExposedByType           map[string]int
}

// trendWindow is the look-back window of the stats trend fields.
const trendWindow = 7 * 24 * time.Hour

// RecentChangeLister is the slice of the asset state-history store the
// "recent changes" block reads. Satisfied by
// *postgres.AssetStateHistoryRepository.
type RecentChangeLister interface {
	List(ctx context.Context, tenantID shared.ID, opts asset.ListStateHistoryOptions) ([]*asset.AssetStateChange, int, error)
	GetAssetRefs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]asset.StateChangeAssetRef, error)
}

// SurfaceService provides attack surface operations.
type SurfaceService struct {
	assetRepo   asset.Repository
	relRepo     asset.RelationshipRepository
	history     RecentChangeLister
	attribution AttributionRecords
	findingRisk FindingRiskCounter
	dataScope   *datascope.Enforcer // Layer 2 narrowing of member-facing reads (nil = unrestricted)
	logger      *logger.Logger
}

// NewSurfaceService creates a new SurfaceService.
func NewSurfaceService(assetRepo asset.Repository, relRepo asset.RelationshipRepository, log *logger.Logger) *SurfaceService {
	return &SurfaceService{
		assetRepo: assetRepo,
		relRepo:   relRepo,
		logger:    log.With("service", "attack_surface"),
	}
}

// SetStateHistory wires the asset state-history store so "recent changes"
// shows real removals and exposure changes, not only additions. Optional.
func (s *SurfaceService) SetStateHistory(h RecentChangeLister) {
	s.history = h
}

// SetFindingRiskCounter wires the KEV/critical finding counter used by
// exposure-chain analysis. Optional: without it, GetExposureChains returns an
// empty result rather than failing.
func (s *SurfaceService) SetFindingRiskCounter(c FindingRiskCounter) {
	s.findingRisk = c
}

// GetAttackPathScores computes attack path scoring for the tenant.
func (s *SurfaceService) GetAttackPathScores(ctx context.Context, tenantID shared.ID) (*PathScoringResult, error) {
	return s.ComputeAttackPathScores(ctx, tenantID, s.relRepo)
}

// GetStats returns attack surface statistics for a tenant.
//
// Layer 2: for a restricted member the asset counts and the two row lists
// (exposed services, recent changes) cover only their in-scope assets. The
// average risk score and the per-type breakdown stay tenant-wide aggregates.
func (s *SurfaceService) GetStats(ctx context.Context, tenantID shared.ID) (*SurfaceStats, error) {
	tenantIDStr := tenantID.String()

	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	// Every count and list here covers attributed assets only (confirmed,
	// dependency, monitor only, or no record): a name a person rejected, one
	// still in review, or one discovery added and nobody claimed is never
	// counted as the organization's exposed surface (research/22 P0-12,
	// research/124).
	population := attribution.FilterAttributed
	if shared.DiscoveredAssetsIncluded(ctx) {
		// The request asked for discovered assets too (include_discovered).
		population = attribution.FilterApproved
	}
	approved, _, _ := attribution.ParseFilter([]string{population})

	// Get total assets count
	totalAssets, err := s.assetRepo.Count(ctx, asset.Filter{
		TenantID: &tenantIDStr,
	}.WithAttribution(approved).WithDataScope(scope))
	if err != nil {
		s.logger.Error("failed to count total assets", "error", err)
		totalAssets = 0
	}

	// Internet-facing assets (the one definition, asset.InternetFacing).
	facing := s.countOrZero(ctx, "internet-facing assets", asset.Filter{
		TenantID: &tenantIDStr,
	}.WithInternetFacing(true).WithAttribution(approved).WithDataScope(scope))
	criticalFacing := s.countOrZero(ctx, "critical internet-facing assets", asset.Filter{
		TenantID:      &tenantIDStr,
		Criticalities: []asset.Criticality{asset.CriticalityCritical, asset.CriticalityHigh},
	}.WithInternetFacing(true).WithAttribution(approved).WithDataScope(scope))

	// Trends: what is new in the last 7 days, with the same data scope as
	// the totals above.
	since := time.Now().UTC().Add(-trendWindow)
	newAssets := s.countOrZero(ctx, "new assets", asset.Filter{
		TenantID:     &tenantIDStr,
		CreatedAfter: &since,
	}.WithAttribution(approved).WithDataScope(scope))
	newlyExposed := s.countNewlyExposed(ctx, tenantID, scope, since)

	// Get assets with risk score for average calculation
	avgRiskScore := s.calculateAverageRiskScore(ctx, tenantID, scope)

	// Get asset breakdown by type
	assetBreakdown := s.getAssetBreakdown(ctx, tenantID, scope)

	// Get exposed services list (limit to 5 for overview)
	exposedServicesList := s.getExposedServicesList(ctx, tenantIDStr, scope, approved, 5)

	// Get recent changes (limit to 5 for overview)
	recentChanges := s.getRecentChanges(ctx, tenantID, scope, 5)

	return &SurfaceStats{
		TotalAssets:                  int(totalAssets),
		InternetFacingAssets:         facing,
		CriticalInternetFacingAssets: criticalFacing,
		RiskScore:                    avgRiskScore,
		TotalAssetsChange:            newAssets,
		NewlyExposed:                 newlyExposed,
		TrendWindowDays:              int(trendWindow / (24 * time.Hour)),
		AssetBreakdown:               assetBreakdown,
		ExposedServicesList:          exposedServicesList,
		RecentChanges:                recentChanges,
	}, nil
}

// calculateAverageRiskScore calculates the average risk score using a single AVG() query.
func (s *SurfaceService) calculateAverageRiskScore(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) float64 {
	avg, err := s.assetRepo.GetAverageRiskScore(ctx, tenantID, scope)
	if err != nil {
		s.logger.Error("failed to get average risk score", "error", err)
		return 0
	}
	return avg
}

// countNewlyExposed counts the "became internet-facing" changes since the
// given time with the caller's data scope: the same query as the newly
// exposed view of Assets > What changed. 0 without a state-history store.
func (s *SurfaceService) countNewlyExposed(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, since time.Time) int {
	if s.history == nil {
		return 0
	}
	opts := asset.NewlyExposedHistory(asset.ListStateHistoryOptions{From: &since, Scope: scope, Limit: 1})
	_, total, err := s.history.List(ctx, tenantID, opts)
	if err != nil {
		s.logger.Error("failed to count newly exposed assets", "error", err)
		return 0
	}
	return total
}

// countOrZero counts assets for a stat card; a failed count is logged and
// shows as 0 rather than failing the whole overview.
func (s *SurfaceService) countOrZero(ctx context.Context, what string, f asset.Filter) int {
	n, err := s.assetRepo.Count(ctx, f)
	if err != nil {
		s.logger.Error("failed to count "+what, "error", err)
		return 0
	}
	return int(n)
}

// getAssetBreakdown returns the count per asset type, with how many are
// exposed, for every type the tenant actually has, largest first.
//
// Legacy type names are folded into their consolidated core type (website,
// api and web_application are stored as application since migration 000130;
// ingest aliases them the same way), so a "Websites" row can no longer sit at
// 0 while the tenant's sites are counted nowhere.
func (s *SurfaceService) getAssetBreakdown(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) []AssetTypeBreakdown {
	statsMap, err := s.assetRepo.GetAssetTypeBreakdown(ctx, tenantID, scope)
	if err != nil {
		s.logger.Error("failed to get asset type breakdown", "error", err)
		return []AssetTypeBreakdown{}
	}
	return foldAssetTypeBreakdown(statsMap)
}

// foldAssetTypeBreakdown is the pure part of getAssetBreakdown.
func foldAssetTypeBreakdown(statsMap map[string]asset.AssetTypeStats) []AssetTypeBreakdown {
	folded := make(map[string]*AssetTypeBreakdown, len(statsMap))
	for t, st := range statsMap {
		if st.Total <= 0 {
			continue
		}
		core, _ := asset.ResolveTypeAlias(asset.AssetType(t))
		key := core.String()
		b, ok := folded[key]
		if !ok {
			b = &AssetTypeBreakdown{Type: key}
			folded[key] = b
		}
		b.Total += st.Total
		b.Exposed += st.Exposed
	}

	breakdown := make([]AssetTypeBreakdown, 0, len(folded))
	for _, b := range folded {
		breakdown = append(breakdown, *b)
	}
	sort.Slice(breakdown, func(i, j int) bool {
		if breakdown[i].Total != breakdown[j].Total {
			return breakdown[i].Total > breakdown[j].Total
		}
		return breakdown[i].Type < breakdown[j].Type
	})
	return breakdown
}

// getExposedServicesList returns the internet-facing (public) assets that
// most need attention: highest risk score first. It lists the same population
// the exposed_services count covers and the external surface page shows.
func (s *SurfaceService) getExposedServicesList(ctx context.Context, tenantID string, scope *shared.DataScope, approved attribution.StateFilter, limit int) []ExposedService {
	opts := asset.NewListOptions().WithSort(
		pagination.NewSortOption(asset.AllowedSortFields()).Parse("-risk_score,-last_seen"),
	)
	result, err := s.assetRepo.List(ctx, asset.Filter{
		TenantID: &tenantID,
	}.WithInternetFacing(true).WithAttribution(approved).WithDataScope(scope), opts, pagination.Pagination{Page: 1, PerPage: limit})
	if err != nil {
		s.logger.Error("failed to get exposed services", "error", err)
		return []ExposedService{}
	}

	services := make([]ExposedService, 0, len(result.Data))
	for _, a := range result.Data {
		services = append(services, ExposedService{
			ID:           a.ID().String(),
			Name:         a.Name(),
			Type:         a.Type().String(),
			Exposure:     a.Exposure().String(),
			Criticality:  a.Criticality().String(),
			FindingCount: a.FindingCount(),
			LastSeen:     a.LastSeen(),
		})
	}

	return services
}

// getRecentChanges returns the latest changes to the inventory, newest first:
//
//   - "added": the most recently created assets (covers every path that adds
//     an asset: scans, imports, manual creation);
//   - "removed" / "changed": asset state history (disappeared, exposure,
//     status, criticality, owner … changes), when the store is wired.
//
// Before this, the block listed assets by creation date and labeled any asset
// updated more than a day after creation "changed", so a re-scan that changed
// nothing looked like a change and nothing was ever "removed".
//
// For a data-scope-restricted member only their in-scope additions are shown:
// state history is tenant-wide and would reveal names of out-of-scope assets.
func (s *SurfaceService) getRecentChanges(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) []AssetChange {
	tenantIDStr := tenantID.String()
	changes := make([]AssetChange, 0, limit*2)
	added := make(map[string]struct{}, limit)

	result, err := s.assetRepo.List(ctx, asset.Filter{
		TenantID: &tenantIDStr,
	}.WithDataScope(scope), asset.ListOptions{}, pagination.Pagination{Page: 1, PerPage: limit})
	if err != nil {
		s.logger.Error("failed to get recently added assets", "error", err)
	} else {
		for _, a := range result.Data {
			added[a.ID().String()] = struct{}{}
			changes = append(changes, AssetChange{
				Type:      "added",
				AssetID:   a.ID().String(),
				AssetName: a.Name(),
				AssetType: a.Type().String(),
				Timestamp: a.CreatedAt(),
			})
		}
	}

	if s.history != nil && scope == nil {
		changes = append(changes, s.historyChanges(ctx, tenantID, limit, added)...)
	}

	sort.SliceStable(changes, func(i, j int) bool {
		return changes[i].Timestamp.After(changes[j].Timestamp)
	})
	if len(changes) > limit {
		changes = changes[:limit]
	}
	s.annotateAttribution(ctx, tenantID, changes)
	return changes
}

// annotateAttribution sets each change's attribution state and inventory
// membership. A failed lookup leaves the states empty (logged).
func (s *SurfaceService) annotateAttribution(ctx context.Context, tenantID shared.ID, changes []AssetChange) {
	for i := range changes {
		changes[i].InInventory = true
	}
	if s.attribution == nil || len(changes) == 0 {
		return
	}
	ids := make([]string, 0, len(changes))
	for _, c := range changes {
		if c.AssetID != "" {
			ids = append(ids, c.AssetID)
		}
	}
	recs, err := s.attribution.Records(ctx, tenantID, ids)
	if err != nil {
		s.logger.Warn("recent changes: attribution lookup failed", "error", err)
		return
	}
	for i := range changes {
		if r, ok := recs[changes[i].AssetID]; ok {
			changes[i].AttributionState = string(r.State)
			changes[i].InInventory = attribution.InInventory(r.State)
		}
	}
}

// historyChanges maps the newest state-history rows to removed/changed
// entries. "appeared" rows of assets already listed as added are skipped so
// one asset does not show twice.
func (s *SurfaceService) historyChanges(ctx context.Context, tenantID shared.ID, limit int, added map[string]struct{}) []AssetChange {
	rows, _, err := s.history.List(ctx, tenantID, asset.ListStateHistoryOptions{Limit: limit * 2})
	if err != nil {
		s.logger.Error("failed to list asset state history", "error", err)
		return nil
	}
	ids := make([]shared.ID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.AssetID())
	}
	refs, err := s.history.GetAssetRefs(ctx, tenantID, ids)
	if err != nil {
		s.logger.Error("failed to resolve asset names for state history", "error", err)
		return nil
	}

	out := make([]AssetChange, 0, len(rows))
	for _, r := range rows {
		ref, ok := refs[r.AssetID()]
		if !ok {
			continue // asset deleted since: no name to show
		}
		kind := "changed"
		switch r.ChangeType() {
		case asset.StateChangeAppeared, asset.StateChangeRecovered:
			if _, dup := added[r.AssetID().String()]; dup {
				continue
			}
			kind = "added"
		case asset.StateChangeDisappeared:
			kind = "removed"
		}
		out = append(out, AssetChange{
			Type:      kind,
			AssetID:   r.AssetID().String(),
			AssetName: ref.Name,
			AssetType: ref.Type,
			Timestamp: r.ChangedAt(),
		})
	}
	return out
}

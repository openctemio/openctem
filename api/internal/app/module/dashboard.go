package module

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// DashboardStats represents aggregated dashboard statistics.
type DashboardStats struct {
	// Asset stats
	AssetCount       int
	AssetsByType     map[string]int
	AssetsBySubType  map[string]int
	AssetsByStatus   map[string]int
	AverageRiskScore float64

	// Finding stats
	FindingCount       int
	FindingsBySeverity map[string]int
	FindingsByStatus   map[string]int
	OverdueFindings    int
	AverageCVSS        float64

	// Repository stats (repositories are assets with type 'repository')
	RepositoryCount          int
	RepositoriesWithFindings int

	// Recent activity
	RecentActivity []ActivityItem

	// Finding trend (monthly breakdown by severity)
	FindingTrend []FindingTrendPoint
}

// FindingTrendPoint represents one month's finding counts by severity.
type FindingTrendPoint struct {
	Date     string // "Jan", "Feb", etc.
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// RiskVelocityPoint represents weekly new vs resolved finding counts.
type RiskVelocityPoint struct {
	Week          time.Time `json:"week"`
	NewCount      int       `json:"new_count"`
	ResolvedCount int       `json:"resolved_count"`
	Velocity      int       `json:"velocity"` // new - resolved (positive = losing ground)
}

// ActivityItem represents a recent activity item.
type ActivityItem struct {
	Type        string
	RefID       string // referenced entity id — the finding UUID when Type=='finding'; empty for aggregate/global activity
	Title       string
	Description string
	Timestamp   time.Time
}

// DashboardAllStats holds all dashboard stats from the optimized batched query.
type DashboardAllStats struct {
	Assets   AssetStatsData
	Findings FindingStatsData
	Repos    RepositoryStatsData
	Activity []ActivityItem
}

// DashboardStatsRepository defines the interface for dashboard data access.
type DashboardStatsRepository interface {
	// GetFindingStats returns finding statistics for a tenant
	GetFindingStats(ctx context.Context, tenantID shared.ID) (FindingStatsData, error)
	// GetRepositoryStats returns repository statistics for a tenant
	GetRepositoryStats(ctx context.Context, tenantID shared.ID) (RepositoryStatsData, error)
	// GetRecentActivity returns recent activity for a tenant
	// (a non-nil scope keeps only findings on in-scope assets).
	GetRecentActivity(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]ActivityItem, error)
	// GetFindingTrend returns monthly finding counts by severity for a tenant
	// (a non-nil scope counts only findings on in-scope assets).
	GetFindingTrend(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, months int) ([]FindingTrendPoint, error)
	// GetAllStats returns all dashboard stats in 2 optimized queries (replaces 10+ individual calls)
	// (a non-nil scope counts only in-scope assets and their findings).
	GetAllStats(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (*DashboardAllStats, error)

	// MTTR & Trending
	// A non-nil scope averages only findings on in-scope assets.
	GetMTTRMetrics(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, days int) (map[string]float64, error)
	GetRiskVelocity(ctx context.Context, tenantID shared.ID, weeks int) ([]RiskVelocityPoint, error)

	// Data Quality Scorecard (RFC-005)
	GetDataQualityScorecard(ctx context.Context, tenantID shared.ID) (*DataQualityScorecard, error)
	// Risk Trend (RFC-005 Gap 4)
	GetRiskTrend(ctx context.Context, tenantID shared.ID, days int) ([]RiskTrendPoint, error)

	// Executive Summary (Phase 2)
	GetExecutiveSummary(ctx context.Context, tenantID shared.ID, days int) (*ExecutiveSummary, error)
	// MTTR Analytics (Phase 2)
	// A non-nil scope averages only findings on in-scope assets.
	GetMTTRAnalytics(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, days int) (*MTTRAnalytics, error)
	// Process Metrics (Phase 2)
	GetProcessMetrics(ctx context.Context, tenantID shared.ID, days int) (*ProcessMetrics, error)
	// CTEM program metrics (MTTD internet-facing, MTTR validated, owner acceptance)
	GetProgramMetrics(ctx context.Context, tenantID shared.ID, days int) (*ProgramMetrics, error)
}

// DataQualityScorecard holds data quality metrics (RFC-005 Gap 5).
type DataQualityScorecard struct {
	AssetOwnershipPct  float64 `json:"asset_ownership_pct"`
	FindingEvidencePct float64 `json:"finding_evidence_pct"`
	MedianLastSeenDays float64 `json:"median_last_seen_days"`
	DeduplicationRate  float64 `json:"deduplication_rate"`
	TotalAssets        int     `json:"total_assets"`
	TotalFindings      int     `json:"total_findings"`

	// Freshness (CTEM Discovery data-quality). MedianLastSeenAgeHours is the
	// median age, in hours, of the most recent observation across ALL assets
	// with a last_seen timestamp (how current the inventory is). StaleAssetPct
	// is the percentage of assets not re-observed in the last 30 days — a
	// coverage-decay signal distinct from MedianLastSeenDays (which is scoped to
	// internet-exposed assets only).
	MedianLastSeenAgeHours float64 `json:"median_last_seen_age_hours"`
	StaleAssetPct          float64 `json:"stale_asset_pct"`
}

// AssetStatsData holds raw asset statistics from repository.
type AssetStatsData struct {
	Total            int
	ByType           map[string]int
	BySubType        map[string]int
	ByStatus         map[string]int
	AverageRiskScore float64
}

// FindingStatsData holds raw finding statistics from repository.
type FindingStatsData struct {
	Total       int
	BySeverity  map[string]int
	ByStatus    map[string]int
	Overdue     int
	AverageCVSS float64
}

// RepositoryStatsData holds raw repository statistics from repository.
type RepositoryStatsData struct {
	Total        int
	WithFindings int
}

// DashboardService provides dashboard-related operations.
type DashboardService struct {
	repo      DashboardStatsRepository
	dataScope *datascope.Enforcer // Layer 2 narrowing of row data (nil = unrestricted)
	logger    *logger.Logger
	// aggregate reports whether the viewer holds dashboard:aggregate.
	aggregate func(ctx context.Context) bool
}

// SetAggregateCheck wires the check for the dashboard:aggregate permission
// (owner decision D6): a restricted viewer who holds it sees organization
// totals, with small breakdowns left out. Without the check nobody does.
func (s *DashboardService) SetAggregateCheck(fn func(ctx context.Context) bool) {
	s.aggregate = fn
}

// dashboardKFloor: in organization totals shown to a restricted viewer, a
// breakdown bucket counting fewer than this many items is left out, so a
// total does not single out an asset the viewer cannot see.
const dashboardKFloor = 5

// countScope decides whose data the dashboard counts: nil (the whole
// organization) for an unrestricted viewer or a restricted viewer holding
// dashboard:aggregate, else the viewer's scope. aggregated is true in the
// second case (apply the k-floor).
func (s *DashboardService) countScope(ctx context.Context, tenantID shared.ID) (scope *shared.DataScope, aggregated bool, err error) {
	scope, err = s.dataScope.Resolve(ctx, tenantID)
	if err != nil || !scope.Restricted() {
		// Unrestricted (nil, or every asset but the private program assets
		// hidden from the viewer): the organization's totals, no k-floor.
		return scope, false, err
	}
	if s.aggregate != nil && s.aggregate(ctx) {
		return nil, true, nil
	}
	return scope, false, nil
}

// kFloor drops breakdown buckets under dashboardKFloor.
func kFloor(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		if v >= dashboardKFloor {
			out[k] = v
		}
	}
	return out
}

// SetDataScope wires the Layer 2 data-scope enforcer. Dashboards keep their
// counts tenant-wide; only row data (recent activity, executive top risks)
// is narrowed for a restricted member.
func (s *DashboardService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// NewDashboardService creates a new DashboardService.
func NewDashboardService(repo DashboardStatsRepository, log *logger.Logger) *DashboardService {
	return &DashboardService{
		repo:   repo,
		logger: log,
	}
}

// GetStats returns dashboard statistics for a tenant.
// Uses optimized batched query (2 queries instead of 10+).
func (s *DashboardService) GetStats(ctx context.Context, tenantID shared.ID) (*DashboardStats, error) {
	// Owner decision D6: the counts follow the viewer. A restricted viewer
	// counts their own scope, unless they hold dashboard:aggregate (then
	// organization totals with the k-floor on breakdowns).
	countScope, aggregated, err := s.countScope(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	// Batched query: all counts + activity in 2 queries
	all, err := s.repo.GetAllStats(ctx, tenantID, countScope)
	if err != nil {
		s.logger.Error("failed to get dashboard stats", "error", err, "tenant_id", tenantID)
		// Fallback to empty
		all = &DashboardAllStats{
			Assets:   AssetStatsData{ByType: make(map[string]int), ByStatus: make(map[string]int)},
			Findings: FindingStatsData{BySeverity: make(map[string]int), ByStatus: make(map[string]int)},
			Activity: []ActivityItem{},
		}
	}

	// Layer 2: recent activity is row data (finding titles and messages), so a
	// restricted member gets it from their in-scope findings only, whatever
	// their aggregate permission.
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if scope != nil {
		activity, aerr := s.repo.GetRecentActivity(ctx, tenantID, scope, dashboardRecentActivityLimit)
		if aerr != nil {
			s.logger.Error("failed to get scoped recent activity", "error", aerr, "tenant_id", tenantID)
			activity = []ActivityItem{}
		}
		all.Activity = activity
	}

	// Finding trend (separate query — different shape, efficient CTE)
	trend, err := s.repo.GetFindingTrend(ctx, tenantID, countScope, 6)
	if err != nil {
		s.logger.Error("failed to get finding trend", "error", err, "tenant_id", tenantID)
		trend = []FindingTrendPoint{}
	}
	if aggregated {
		all.Assets.ByType = kFloor(all.Assets.ByType)
		all.Assets.BySubType = kFloor(all.Assets.BySubType)
		all.Assets.ByStatus = kFloor(all.Assets.ByStatus)
		all.Findings.BySeverity = kFloor(all.Findings.BySeverity)
		all.Findings.ByStatus = kFloor(all.Findings.ByStatus)
	}

	return &DashboardStats{
		AssetCount:               all.Assets.Total,
		AssetsByType:             all.Assets.ByType,
		AssetsBySubType:          all.Assets.BySubType,
		AssetsByStatus:           all.Assets.ByStatus,
		AverageRiskScore:         all.Assets.AverageRiskScore,
		FindingCount:             all.Findings.Total,
		FindingsBySeverity:       all.Findings.BySeverity,
		FindingsByStatus:         all.Findings.ByStatus,
		OverdueFindings:          all.Findings.Overdue,
		AverageCVSS:              all.Findings.AverageCVSS,
		RepositoryCount:          all.Repos.Total,
		RepositoriesWithFindings: all.Repos.WithFindings,
		RecentActivity:           all.Activity,
		FindingTrend:             trend,
	}, nil
}

// GetMTTRMetrics returns MTTR (Mean Time To Remediate) in hours by severity.
// It follows the viewer like the other dashboard numbers (countScope): a
// restricted member averages their own findings only (research 24 §5.1).
func (s *DashboardService) GetMTTRMetrics(ctx context.Context, tenantID shared.ID, days int) (map[string]float64, error) {
	scope, _, err := s.countScope(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	return s.repo.GetMTTRMetrics(ctx, tenantID, scope, days)
}

// GetRiskVelocity returns weekly new vs resolved finding counts.
func (s *DashboardService) GetRiskVelocity(ctx context.Context, tenantID shared.ID, weeks int) ([]RiskVelocityPoint, error) {
	return s.repo.GetRiskVelocity(ctx, tenantID, weeks)
}

// GetDataQualityScorecard returns data quality metrics (RFC-005 Gap 5).
func (s *DashboardService) GetDataQualityScorecard(ctx context.Context, tenantID shared.ID) (*DataQualityScorecard, error) {
	return s.repo.GetDataQualityScorecard(ctx, tenantID)
}

// GetRiskTrend returns risk snapshot time-series (RFC-005 Gap 4).
func (s *DashboardService) GetRiskTrend(ctx context.Context, tenantID shared.ID, days int) ([]RiskTrendPoint, error) {
	return s.repo.GetRiskTrend(ctx, tenantID, days)
}

// RiskTrendPoint represents a single point in a risk trend time-series.
type RiskTrendPoint struct {
	Date             string  `json:"date"`
	RiskScoreAvg     float64 `json:"risk_score_avg"`
	FindingsOpen     int     `json:"findings_open"`
	SLACompliancePct float64 `json:"sla_compliance_pct"`
	P0Open           int     `json:"p0_open"`
	P1Open           int     `json:"p1_open"`
	P2Open           int     `json:"p2_open"`
	P3Open           int     `json:"p3_open"`
}

// ExecutiveSummary holds executive-level metrics for a time period.
type ExecutiveSummary struct {
	Period            string    `json:"period"`
	RiskScoreCurrent  float64   `json:"risk_score_current"`
	RiskScoreChange   float64   `json:"risk_score_change"`
	FindingsTotal     int       `json:"findings_total"`
	FindingsResolved  int       `json:"findings_resolved_period"`
	FindingsNew       int       `json:"findings_new_period"`
	P0Open            int       `json:"p0_open"`
	P0Resolved        int       `json:"p0_resolved_period"`
	P1Open            int       `json:"p1_open"`
	P1Resolved        int       `json:"p1_resolved_period"`
	SLACompliancePct  float64   `json:"sla_compliance_pct"`
	SLABreached       int       `json:"sla_breached"`
	MTTRCriticalHrs   float64   `json:"mttr_critical_hours"`
	MTTRHighHrs       float64   `json:"mttr_high_hours"`
	CrownJewelsAtRisk int       `json:"crown_jewels_at_risk"`
	RegressionCount   int       `json:"regression_count"`
	RegressionRatePct float64   `json:"regression_rate_pct"`
	TopRisks          []TopRisk `json:"top_risks"`
}

// TopRisk represents a high-priority open finding for executive view.
type TopRisk struct {
	FindingID     string   `json:"finding_id"`
	FindingTitle  string   `json:"title"`
	Severity      string   `json:"severity"`
	PriorityClass string   `json:"priority_class"`
	AssetID       string   `json:"asset_id,omitempty"`
	AssetName     string   `json:"asset_name"`
	EPSSScore     *float64 `json:"epss_score"`
	IsInKEV       bool     `json:"is_in_kev"`
}

// MTTRAnalytics holds MTTR breakdown by severity and priority class.
type MTTRAnalytics struct {
	BySeverity      map[string]float64 `json:"by_severity"`
	ByPriorityClass map[string]float64 `json:"by_priority_class"`
	Overall         float64            `json:"overall_hours"`
	SampleSize      int                `json:"sample_size"`
}

// ProcessMetrics holds process efficiency metrics.
type ProcessMetrics struct {
	ApprovalAvgHours     float64 `json:"approval_avg_hours"`
	ApprovalCount        int     `json:"approval_count"`
	RetestAvgHours       float64 `json:"retest_avg_hours"`
	RetestCount          int     `json:"retest_count"`
	StaleAssets          int     `json:"stale_assets"`
	StaleAssetsPct       float64 `json:"stale_assets_pct"`
	FindingsWithoutOwner int     `json:"findings_without_owner"`
	AvgTimeToAssignHours float64 `json:"avg_time_to_assign_hours"`
}

// ProgramMetrics holds the CTEM program metrics ctem.org asks a program to
// report that can be computed honestly from data the platform already stores.
// Every figure is tenant-scoped and windowed to the last PeriodDays days.
//
// A nil pointer means "not measurable" (no qualifying sample in the window) —
// never 0 and never 100%. Clients must render nil as "—".
//
// Deliberately NOT here: time-to-break attack paths. Attack paths / exposure
// chains are computed on demand from the current asset graph
// (internal/app/attack/exposure_chains.go) and never persisted, and neither asset
// exposure nor asset relationships keep a change history. There is therefore
// no record of when a path opened or when one of its links was broken, and any
// "time to break" figure would be invented.
type ProgramMetrics struct {
	PeriodDays int `json:"period_days"`

	// MTTDInternetFacing — mean time to detect new internet-facing assets.
	//
	// Population: non-archived assets whose first_seen falls in the window and
	// that are internet-facing now (exposure = 'public' OR
	// is_internet_accessible).
	//
	// Clock start: assets.first_seen (the asset entered the inventory).
	// Clock stop: the EARLIEST of these per-asset signals that it was known to
	// be internet-facing or exposed —
	//   - assets.exposure_changed_at, when the current exposure is 'public'
	//     (stamped when the exposure level was classified);
	//   - asset_state_history rows of change_type exposure_changed /
	//     internet_exposure_changed whose new_value is 'public' / 'true';
	//   - the asset's first exposure event (exposure_events.first_seen_at);
	//   - the asset's first finding (findings.first_detected_at).
	// A stop before first_seen counts as 0 h (known at discovery). Assets with
	// no stop signal at all are not averaged; they are counted in Unmeasured.
	//
	// Caveat: exposure_changed_at holds the LAST exposure change, so an asset
	// that flapped public → private → public is measured to the later flip
	// unless an earlier history row / exposure / finding exists.
	MTTDInternetFacing DurationMetric `json:"mttd_internet_facing"`

	// MTTRValidated — mean time to remediate VALIDATED exposures only.
	//
	// Population: findings with at least one validation_evidence row of
	// outcome 'detected' (the validation re-check reproduced the exposure —
	// "still exploitable", RFC-011.2 VerdictReproducible), now in status
	// resolved / verified, with resolved_at in the window.
	//
	// Clock start: the first 'detected' validation_evidence.created_at.
	// Clock stop: findings.resolved_at. Findings resolved before they were
	// validated are excluded (the fix did not follow the validation).
	// false_positive / accepted / validated_fixed are not remediation and are
	// excluded.
	MTTRValidated DurationMetric `json:"mttr_validated"`

	// OwnerAcceptance — share of assignments the assignee acted on within the
	// SLA window. See OwnerAcceptanceMetric.
	OwnerAcceptance OwnerAcceptanceMetric `json:"owner_acceptance"`
}

// DurationMetric is a mean/median duration over a sample, in hours.
// MeanHours / MedianHours are nil when SampleSize is 0.
type DurationMetric struct {
	MeanHours   *float64 `json:"mean_hours"`
	MedianHours *float64 `json:"median_hours"`
	SampleSize  int      `json:"sample_size"`
	// Unmeasured counts population members that had no stop signal and so
	// could not be timed (MTTD only; always 0 for MTTR).
	Unmeasured int `json:"unmeasured"`
}

// OwnerAcceptanceMetric — owner acceptance rate.
//
// Unit: one 'assigned' finding_activities event made in the window that names
// an assignee (changes->>'assignee_id').
//
// Response window: from the assignment until the EARLIEST of the finding's
// SLA deadline (findings.sla_deadline), the next assign/unassign on that
// finding, or the finding being resolved.
//
// Acted: the assignee themself (actor_type 'user', actor_id = assignee)
// recorded one of status_changed, triage_updated, severity_changed,
// comment_added, remediation_updated, resolved, verified,
// false_positive_marked, duplicate_marked, approval_requested within the
// response window.
//
// Outcome of each assignment:
//   - Accepted: acted within the window.
//   - Missed: not acted and the SLA deadline has passed with the assignee
//     still responsible.
//   - Pending: not acted, SLA deadline still in the future — undecided, so not
//     in the rate.
//   - Excluded: no SLA deadline, assigned after the deadline had already
//     passed, or the assignee was relieved before the deadline without acting
//     (reassigned / unassigned / someone else resolved the finding).
//
// RatePct = Accepted / (Accepted + Missed) × 100, nil when that is 0.
type OwnerAcceptanceMetric struct {
	RatePct  *float64 `json:"rate_pct"`
	Accepted int      `json:"accepted"`
	Missed   int      `json:"missed"`
	Pending  int      `json:"pending"`
	Excluded int      `json:"excluded"`
}

// GetProgramMetrics returns the CTEM program metrics for a tenant.
func (s *DashboardService) GetProgramMetrics(ctx context.Context, tenantID shared.ID, days int) (*ProgramMetrics, error) {
	return s.repo.GetProgramMetrics(ctx, tenantID, days)
}

// GetProcessMetrics returns process efficiency metrics.
func (s *DashboardService) GetProcessMetrics(ctx context.Context, tenantID shared.ID, days int) (*ProcessMetrics, error) {
	return s.repo.GetProcessMetrics(ctx, tenantID, days)
}

// GetExecutiveSummary returns executive-level metrics for a time period.
// Layer 2: TopRisks (finding titles and asset names) keeps only in-scope
// assets for a restricted member; the metrics stay tenant-wide.
func (s *DashboardService) GetExecutiveSummary(ctx context.Context, tenantID shared.ID, days int) (*ExecutiveSummary, error) {
	sum, err := s.repo.GetExecutiveSummary(ctx, tenantID, days)
	if err != nil || sum == nil {
		return sum, err
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if scope == nil || len(sum.TopRisks) == 0 {
		return sum, nil
	}
	ids := make([]shared.ID, 0, len(sum.TopRisks))
	for _, r := range sum.TopRisks {
		if id, perr := shared.IDFromString(r.AssetID); perr == nil {
			ids = append(ids, id)
		}
	}
	keep, err := s.dataScope.Filter(ctx, scope, ids)
	if err != nil {
		return nil, err
	}
	top := make([]TopRisk, 0, len(sum.TopRisks))
	for _, r := range sum.TopRisks {
		if id, perr := shared.IDFromString(r.AssetID); perr == nil && keep(id) {
			top = append(top, r)
		}
	}
	sum.TopRisks = top
	return sum, nil
}

// GetMTTRAnalytics returns MTTR breakdown by severity and priority class.
// It follows the viewer like GetMTTRMetrics.
func (s *DashboardService) GetMTTRAnalytics(ctx context.Context, tenantID shared.ID, days int) (*MTTRAnalytics, error) {
	scope, _, err := s.countScope(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	return s.repo.GetMTTRAnalytics(ctx, tenantID, scope, days)
}

// dashboardRecentActivityLimit is how many recent findings the dashboards show.
const dashboardRecentActivityLimit = 10

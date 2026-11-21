package threat

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatintel"
	"github.com/openctemio/openctem/server/pkg/logger"
)

const (
	// epssHighThreshold is the EPSS probability at or above which a CVE is
	// treated as "high" exploitation risk (10% chance of exploitation in the
	// next 30 days). Long-standing "elevated attention" line.
	epssHighThreshold = 0.1

	// epssCriticalThreshold is the EPSS probability at or above which a CVE is
	// treated as "critical" exploitation risk on the tenant dashboard. FIRST
	// publishes no fixed EPSS severity bands, so we pick a defensible line:
	// 0.5 means the model estimates the vulnerability is more likely than not
	// (>50%) to be exploited in the next 30 days. The previous 0.3 threshold
	// was undocumented and weak — a ~30% probability is common for many recent
	// CVEs, which over-counted the "critical" bucket. 0.5 keeps it small and
	// actionable.
	epssCriticalThreshold = 0.5

	// catalogCountsTTL bounds how long the global EPSS/KEV catalog counts
	// shown on /threat-intel/stats are reused. The catalogs change only when
	// a sync runs (daily), and a successful sync on this replica drops the
	// cache immediately, so the TTL only matters for syncs that ran on
	// another replica.
	catalogCountsTTL = 5 * time.Minute
)

// epssCatalogCounts / kevCatalogCounts are the tenant-independent figures of
// the EPSS and KEV catalogs shown on /threat-intel/stats. COUNT(*) over the
// ~380k-row epss_scores table alone costs ~24ms on every request, which the
// dashboard polls; the values only change when a sync runs, so they are
// cached. EPSS and KEV are cached separately so a failure reading one catalog
// still degrades gracefully to partial stats, exactly as before.
type epssCatalogCounts struct {
	total     int64
	fetchedAt time.Time
}

type kevCatalogCounts struct {
	total      int64
	recent30d  int64
	ransomware int64
	fetchedAt  time.Time
}

// IntelService handles threat intelligence operations. It makes no outbound
// call: KEV and EPSS arrive only in the signed vulnerability release, fetched
// from the feed origin or through a relay sensor (intel_bundle.go); the
// platform talks only to its own sensors and its configured feed origin.
type IntelService struct {
	repo   threatintel.ThreatIntelRepository
	logger *logger.Logger

	// countsMu guards counts. Only global catalog figures are cached here;
	// tenant-scoped counts are always read fresh.
	countsMu   sync.Mutex
	epssCounts *epssCatalogCounts
	kevCounts  *kevCatalogCounts
	now        func() time.Time

	// afterBundle runs after KEV or EPSS was applied from a release (nil:
	// nothing), see intel_bundle.go.
	afterBundle func(ctx context.Context, source string)
}

// NewIntelService creates a new IntelService.
func NewIntelService(
	repo threatintel.ThreatIntelRepository,
	log *logger.Logger,
) *IntelService {
	return &IntelService{
		repo:   repo,
		logger: log.With("service", "threat_intel"),
		now:    time.Now,
	}
}

// invalidateCatalogCounts drops the cached catalog counts so the next stats
// request re-reads them. Called after a successful EPSS/KEV sync.
func (s *IntelService) invalidateCatalogCounts() {
	s.countsMu.Lock()
	s.epssCounts = nil
	s.kevCounts = nil
	s.countsMu.Unlock()
}

// getEPSSCatalogCounts returns the global EPSS catalog size from a
// short-lived in-process cache. Errors are never cached.
func (s *IntelService) getEPSSCatalogCounts(ctx context.Context) (epssCatalogCounts, error) {
	s.countsMu.Lock()
	if c := s.epssCounts; c != nil && s.now().Sub(c.fetchedAt) < catalogCountsTTL {
		s.countsMu.Unlock()
		return *c, nil
	}
	s.countsMu.Unlock()

	total, err := s.repo.EPSS().Count(ctx)
	if err != nil {
		return epssCatalogCounts{}, err
	}
	c := epssCatalogCounts{total: total, fetchedAt: s.now()}

	s.countsMu.Lock()
	s.epssCounts = &c
	s.countsMu.Unlock()
	return c, nil
}

// getKEVCatalogCounts returns the global KEV catalog figures from a
// short-lived in-process cache. Errors are never cached.
func (s *IntelService) getKEVCatalogCounts(ctx context.Context) (kevCatalogCounts, error) {
	s.countsMu.Lock()
	if c := s.kevCounts; c != nil && s.now().Sub(c.fetchedAt) < catalogCountsTTL {
		s.countsMu.Unlock()
		return *c, nil
	}
	s.countsMu.Unlock()

	var (
		c   kevCatalogCounts
		err error
	)
	if c.total, err = s.repo.KEV().Count(ctx); err != nil {
		return kevCatalogCounts{}, err
	}
	if c.recent30d, err = s.repo.KEV().CountRecentlyAdded(ctx, 30); err != nil {
		return kevCatalogCounts{}, err
	}
	if c.ransomware, err = s.repo.KEV().CountRansomwareRelated(ctx); err != nil {
		return kevCatalogCounts{}, err
	}
	c.fetchedAt = s.now()

	s.countsMu.Lock()
	s.kevCounts = &c
	s.countsMu.Unlock()
	return c, nil
}

// KEVEscalationResult reports what a KEV reconciliation pass changed.
//
// Flagged and Unflagged count is_in_kev changes; severity is never changed
// (KEV feeds the priority classifier's exploitation floor instead). Tenants
// is the distinct set of tenants touched by either change.
type KEVEscalationResult struct {
	// Flagged is the number of findings whose is_in_kev was reconciled
	// from false to true (independent of severity).
	Flagged int
	// Unflagged is the number of findings whose is_in_kev was cleared because
	// their CVE is no longer in KEV.
	Unflagged int
	// Tenants is the distinct set of tenant IDs with at least one finding
	// touched by either the escalation or the is_in_kev reconciliation.
	Tenants []shared.ID
}

// KEVEscalator auto-escalates findings whose CVEs appear in the CISA KEV catalog.
type KEVEscalator interface {
	// EscalateKEVFindings raises severity to 'critical' for non-critical open
	// findings whose cve_id is in the kev_catalog, AND reconciles is_in_kev to
	// true for every non-terminal finding whose cve_id is in the catalog
	// (independent of severity). Returns what changed, including the distinct
	// tenants touched so the caller can trigger priority reclassification.
	EscalateKEVFindings(ctx context.Context) (KEVEscalationResult, error)
}

// propagateToCatalog makes the shared vulnerabilities catalog agree with the
// feeds just synced. A failure is logged, not returned: the feed itself was
// stored, and the next sync propagates again.
func (s *IntelService) propagateToCatalog(ctx context.Context, source string) {
	n, err := s.repo.PropagateToVulnerabilityCatalog(ctx)
	if err != nil {
		s.logger.Error("failed to propagate threat intel to the vulnerability catalog", "source", source, "error", err)
		return
	}
	s.logger.Info("vulnerability catalog updated from threat intel", "source", source, "rows", n)
}

// markFailed records a failed sync with its classification. The stored text
// is shown on the platform admin route: URL credentials are removed first.
func markFailed(status *threatintel.SyncStatus, err error) {
	c := feedstatus.Classify(err)
	status.MarkSyncFailedWith(logger.RedactURLs(err.Error()), c.Code, c.Params)
}

// maxKEVRemovalsPerSync bounds how many CVEs one sync may remove from the KEV
// catalog. CISA removes entries rarely (a handful in the catalog's history);
// a feed that would remove more than this, or more than kevMaxRemovalShare of
// the catalog, is more likely truncated or wrong than a real change, so the
// prune is skipped and logged and the next sync tries again.
const (
	maxKEVRemovalsPerSync = 25
	kevMaxRemovalShare    = 0.02
)

// pruneRemovedKEV removes the KEV entries that are not in the feed just
// stored, so a CVE CISA took off the list stops counting as known-exploited.
// The catalog propagation and the findings reconciliation that follow then
// clear the flags they had set. Errors are logged: the upsert succeeded and
// the next sync prunes again.
func (s *IntelService) pruneRemovedKEV(ctx context.Context, entries []*threatintel.KEVEntry) {
	if len(entries) == 0 {
		return
	}
	keep := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		id := e.CVEID()
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		keep = append(keep, id)
	}
	total, err := s.repo.KEV().Count(ctx)
	if err != nil {
		s.logger.Error("KEV prune skipped: count failed", "error", err)
		return
	}
	removals := total - int64(len(keep))
	if removals <= 0 {
		return
	}
	if removals > maxKEVRemovalsPerSync || float64(removals) > kevMaxRemovalShare*float64(total) {
		s.logger.Warn("KEV prune skipped: the feed would remove too many entries",
			"would_remove", removals, "catalog", total, "feed", len(keep))
		return
	}
	n, err := s.repo.KEV().PruneNotIn(ctx, keep)
	if err != nil {
		s.logger.Error("KEV prune failed", "error", err)
		return
	}
	if n > 0 {
		s.logger.Info("removed CVEs that left the KEV catalog", "removed", n)
	}
}

// GetSyncStatuses returns all sync statuses.
func (s *IntelService) GetSyncStatuses(ctx context.Context) ([]*threatintel.SyncStatus, error) {
	return s.repo.SyncStatus().GetAll(ctx)
}

// GetSyncStatus returns sync status for a specific source.
func (s *IntelService) GetSyncStatus(ctx context.Context, source string) (*threatintel.SyncStatus, error) {
	return s.repo.SyncStatus().GetBySource(ctx, source)
}

// SetSyncEnabled enables or disables sync for a source.
func (s *IntelService) SetSyncEnabled(ctx context.Context, source string, enabled bool) error {
	status, err := s.repo.SyncStatus().GetBySource(ctx, source)
	if err != nil {
		return err
	}
	status.SetEnabled(enabled)
	return s.repo.SyncStatus().Update(ctx, status)
}

// EnrichCVEs enriches multiple CVEs with threat intel data.
func (s *IntelService) EnrichCVEs(ctx context.Context, cveIDs []string) (map[string]*threatintel.ThreatIntelEnrichment, error) {
	return s.repo.EnrichCVEs(ctx, cveIDs)
}

// EnrichCVE enriches a single CVE with threat intel data.
func (s *IntelService) EnrichCVE(ctx context.Context, cveID string) (*threatintel.ThreatIntelEnrichment, error) {
	return s.repo.EnrichCVE(ctx, cveID)
}

// GetEPSSScore retrieves an EPSS score by CVE ID.
func (s *IntelService) GetEPSSScore(ctx context.Context, cveID string) (*threatintel.EPSSScore, error) {
	return s.repo.EPSS().GetByCVEID(ctx, cveID)
}

// GetEPSSScores retrieves EPSS scores for multiple CVE IDs.
func (s *IntelService) GetEPSSScores(ctx context.Context, cveIDs []string) ([]*threatintel.EPSSScore, error) {
	return s.repo.EPSS().GetByCVEIDs(ctx, cveIDs)
}

// GetHighRiskEPSS retrieves high-risk EPSS scores.
func (s *IntelService) GetHighRiskEPSS(ctx context.Context, threshold float64, limit int) ([]*threatintel.EPSSScore, error) {
	return s.repo.EPSS().GetHighRisk(ctx, threshold, limit)
}

// GetKEVEntry retrieves a KEV entry by CVE ID.
func (s *IntelService) GetKEVEntry(ctx context.Context, cveID string) (*threatintel.KEVEntry, error) {
	return s.repo.KEV().GetByCVEID(ctx, cveID)
}

// IsInKEV checks if a CVE is in the KEV catalog.
func (s *IntelService) IsInKEV(ctx context.Context, cveID string) (bool, error) {
	return s.repo.KEV().ExistsByCVEID(ctx, cveID)
}

// GetKEVStats returns KEV statistics.
func (s *IntelService) GetKEVStats(ctx context.Context) (*KEVStats, error) {
	total, err := s.repo.KEV().Count(ctx)
	if err != nil {
		return nil, err
	}

	pastDue, err := s.repo.KEV().GetPastDue(ctx, 1000)
	if err != nil {
		return nil, err
	}

	recentlyAdded, err := s.repo.KEV().GetRecentlyAdded(ctx, 30, 1000)
	if err != nil {
		return nil, err
	}

	ransomwareRelated, err := s.repo.KEV().GetRansomwareRelated(ctx, 1000)
	if err != nil {
		return nil, err
	}

	return &KEVStats{
		TotalEntries:            int(total),
		PastDueCount:            len(pastDue),
		RecentlyAddedLast30Days: len(recentlyAdded),
		RansomwareRelatedCount:  len(ransomwareRelated),
	}, nil
}

// GetEPSSStats returns EPSS statistics.
func (s *IntelService) GetEPSSStats(ctx context.Context) (*EPSSStats, error) {
	total, err := s.repo.EPSS().Count(ctx)
	if err != nil {
		return nil, err
	}

	highRisk, err := s.repo.EPSS().GetHighRisk(ctx, 0.1, 10000)
	if err != nil {
		return nil, err
	}

	criticalRisk, err := s.repo.EPSS().GetHighRisk(ctx, 0.3, 10000)
	if err != nil {
		return nil, err
	}

	return &EPSSStats{
		TotalScores:       int(total),
		HighRiskCount:     len(highRisk),     // EPSS > 0.1
		CriticalRiskCount: len(criticalRisk), // EPSS > 0.3
	}, nil
}

// GetKEVStatsForTenant returns KEV statistics for one tenant. The tenant
// figures (open in KEV, past due, ransomware, new in the last 30 days) count
// the tenant's OPEN findings in the reader's data scope; they are never
// cached. The catalog figures (total, ransomware entries, entries added in 30
// days) describe the global feed, are identical for every tenant and are
// labeled as catalog figures wherever they are shown.
func (s *IntelService) GetKEVStatsForTenant(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (*KEVStats, error) {
	catalog, err := s.getKEVCatalogCounts(ctx)
	if err != nil {
		return nil, err
	}

	// Tenant-scoped: never cached.
	tenant, err := s.repo.KEV().CountTenantOpenKEV(ctx, tenantID, scope)
	if err != nil {
		return nil, err
	}

	return &KEVStats{
		TotalEntries:              int(catalog.total),
		TenantOpenCount:           int(tenant.Open),
		PastDueCount:              int(tenant.PastDue),
		TenantRansomwareOpenCount: int(tenant.Ransomware),
		TenantNewMatches30Days:    int(tenant.NewLast30Days),
		RecentlyAddedLast30Days:   int(catalog.recent30d),
		RansomwareRelatedCount:    int(catalog.ransomware),
	}, nil
}

// GetEPSSStatsForTenant returns EPSS statistics scoped to a single tenant's
// exposure. Unlike GetEPSSStats (which reports global catalog figures identical
// for every tenant and saturates its LIMIT-bounded counts), the high/critical
// figures here count the tenant's OPEN findings whose CVE meets the EPSS
// threshold — the tenant's real exploitation-probability exposure.
func (s *IntelService) GetEPSSStatsForTenant(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (*EPSSStats, error) {
	catalog, err := s.getEPSSCatalogCounts(ctx)
	if err != nil {
		return nil, err
	}
	total := catalog.total

	// Both buckets in ONE join of the tenant's findings to epss_scores
	// (previously two identical joins differing only in the threshold).
	counts, err := s.repo.EPSS().CountTenantOpenAboveScores(ctx, tenantID, scope,
		[]float64{epssHighThreshold, epssCriticalThreshold})
	if err != nil {
		return nil, err
	}
	if len(counts) != 2 {
		return nil, fmt.Errorf("epss tenant counts: want 2 buckets, got %d", len(counts))
	}

	return &EPSSStats{
		TotalScores:       int(total),
		HighRiskCount:     int(counts[0]),
		CriticalRiskCount: int(counts[1]),
	}, nil
}

// GetThreatIntelStats returns unified threat intelligence statistics for a
// tenant. A non-nil scope counts only the findings on assets inside that
// data scope (nil: the whole tenant). This combines tenant-scoped EPSS stats, tenant-scoped KEV stats, and
// (global) sync statuses in a single call. The KEV/EPSS figures reflect the
// tenant's exposure, not the global CISA/EPSS catalog.
func (s *IntelService) GetThreatIntelStats(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (*ThreatIntelStats, error) {
	stats := &ThreatIntelStats{}

	// Get EPSS stats (continue even if error - partial data is OK)
	epssStats, err := s.GetEPSSStatsForTenant(ctx, tenantID, scope)
	if err != nil {
		s.logger.Warn("failed to get EPSS stats", "error", err)
	} else {
		stats.EPSS = epssStats
	}

	// Get KEV stats
	kevStats, err := s.GetKEVStatsForTenant(ctx, tenantID, scope)
	if err != nil {
		s.logger.Warn("failed to get KEV stats", "error", err)
	} else {
		stats.KEV = kevStats
	}

	// Get sync statuses
	syncStatuses, err := s.repo.SyncStatus().GetAll(ctx)
	if err != nil {
		s.logger.Warn("failed to get sync statuses", "error", err)
		stats.SyncStatuses = []*ThreatIntelSyncDTO{}
	} else {
		stats.SyncStatuses = make([]*ThreatIntelSyncDTO, 0, len(syncStatuses))
		for _, status := range syncStatuses {
			dto := &ThreatIntelSyncDTO{
				Source:         status.SourceName(),
				Enabled:        status.IsEnabled(),
				LastSyncStatus: status.LastSyncStatus().String(),
				RecordsSynced:  status.RecordsSynced(),
			}

			if status.LastSyncAt() != nil {
				t := status.LastSyncAt().Format("2006-01-02T15:04:05Z")
				dto.LastSyncAt = &t
			}

			if status.NextSyncAt() != nil {
				t := status.NextSyncAt().Format("2006-01-02T15:04:05Z")
				dto.NextSyncAt = &t
			}

			stats.SyncStatuses = append(stats.SyncStatuses, dto)
		}
	}

	return stats, nil
}

// KEVStats contains KEV statistics. The tenant_* and past_due_count figures
// are the tenant's open findings in the reader's scope; total_entries,
// recently_added_last_30_days and ransomware_related_count describe the
// global catalog.
type KEVStats struct {
	TotalEntries              int `json:"total_entries"`                // catalog: entries in the KEV catalog
	TenantOpenCount           int `json:"tenant_open_count"`            // tenant: open findings in the KEV catalog
	PastDueCount              int `json:"past_due_count"`               // tenant: of those, KEV due date passed
	TenantRansomwareOpenCount int `json:"tenant_ransomware_open_count"` // tenant: of those, known ransomware use
	TenantNewMatches30Days    int `json:"tenant_new_kev_matches_30d"`   // tenant: of those, CVE added to KEV in the last 30 days
	RecentlyAddedLast30Days   int `json:"recently_added_last_30_days"`  // catalog: entries added in the last 30 days
	RansomwareRelatedCount    int `json:"ransomware_related_count"`     // catalog: entries with known ransomware use
}

// EPSSStats contains EPSS statistics. When produced by GetEPSSStatsForTenant
// (the /threat-intel/stats dashboard path), the counts are tenant-scoped:
// HighRiskCount / CriticalRiskCount are the tenant's OPEN findings whose CVE
// has an EPSS score >= epssHighThreshold / epssCriticalThreshold.
type EPSSStats struct {
	TotalScores       int `json:"total_scores"`
	HighRiskCount     int `json:"high_risk_count"`     // EPSS >= epssHighThreshold (0.1)
	CriticalRiskCount int `json:"critical_risk_count"` // EPSS >= epssCriticalThreshold (0.5)
}

// ThreatIntelStats contains unified threat intelligence statistics.
type ThreatIntelStats struct {
	EPSS         *EPSSStats            `json:"epss"`
	KEV          *KEVStats             `json:"kev"`
	SyncStatuses []*ThreatIntelSyncDTO `json:"sync_statuses"`
}

// ThreatIntelSyncDTO is a data transfer object for sync status.
type ThreatIntelSyncDTO struct {
	Source         string  `json:"source"`
	Enabled        bool    `json:"enabled"`
	LastSyncAt     *string `json:"last_sync_at,omitempty"`
	LastSyncStatus string  `json:"last_sync_status"`
	RecordsSynced  int     `json:"records_synced"`
	NextSyncAt     *string `json:"next_sync_at,omitempty"`
}

// FeedEnabled reports whether a feed's scheduled sync is on
// (threatintel.ErrSyncStatusNotFound when the source is unknown).
func (s *IntelService) FeedEnabled(ctx context.Context, source string) (bool, error) {
	rows, err := s.repo.SyncStatus().GetAll(ctx)
	if err != nil {
		return false, err
	}
	for _, st := range rows {
		if st.SourceName() == source {
			return st.IsEnabled(), nil
		}
	}
	return false, threatintel.ErrSyncStatusNotFound
}

// FeedView returns the view of one feed (threatintel.ErrSyncStatusNotFound
// when the source is unknown).
func (s *IntelService) FeedView(ctx context.Context, source string) (feedstatus.View, error) {
	views, err := s.FeedViews(ctx)
	if err != nil {
		return feedstatus.View{}, err
	}
	for _, v := range views {
		if v.Source == source {
			return v, nil
		}
	}
	return feedstatus.View{}, threatintel.ErrSyncStatusNotFound
}

// FeedViews returns the status of every feed as the platform admin console
// shows it: one state, an error code, honest times and catalog sizes.
func (s *IntelService) FeedViews(ctx context.Context) ([]feedstatus.View, error) {
	rows, err := s.repo.SyncStatus().GetAll(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	out := make([]feedstatus.View, 0, len(rows))
	for _, st := range rows {
		var catalog int64
		switch st.SourceName() {
		case feedstatus.SourceEPSS:
			if c, cerr := s.getEPSSCatalogCounts(ctx); cerr == nil {
				catalog = c.total
			}
		case feedstatus.SourceKEV:
			if c, cerr := s.getKEVCatalogCounts(ctx); cerr == nil {
				catalog = c.total
			}
		}
		out = append(out, feedstatus.Build(st, catalog, now))
	}
	return out, nil
}

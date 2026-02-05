package app

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/threatintel"
	"github.com/openctemio/api/pkg/logger"
)

const (
	// EPSS data source URL (gzipped CSV)
	epssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

	// KEV catalog URL (JSON)
	kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// HTTP client timeout
	httpTimeout = 5 * time.Minute
)

// ThreatIntelService handles threat intelligence operations.
type ThreatIntelService struct {
	repo       threatintel.ThreatIntelRepository
	httpClient *http.Client
	logger     *logger.Logger
}

// NewThreatIntelService creates a new ThreatIntelService.
func NewThreatIntelService(
	repo threatintel.ThreatIntelRepository,
	log *logger.Logger,
) *ThreatIntelService {
	return &ThreatIntelService{
		repo: repo,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		logger: log.With("service", "threat_intel"),
	}
}

// ThreatIntelSyncResult contains the result of a sync operation.
type ThreatIntelSyncResult struct {
	Source        string
	RecordsSynced int
	DurationMs    int64
	Error         error
}

// SyncAll syncs all enabled threat intel sources.
func (s *ThreatIntelService) SyncAll(ctx context.Context) []ThreatIntelSyncResult {
	results := make([]ThreatIntelSyncResult, 0, 2)

	// Sync EPSS
	epssResult := s.SyncEPSS(ctx)
	results = append(results, epssResult)

	// Sync KEV
	kevResult := s.SyncKEV(ctx)
	results = append(results, kevResult)

	return results
}

// SyncEPSS syncs EPSS scores from FIRST.org.
func (s *ThreatIntelService) SyncEPSS(ctx context.Context) ThreatIntelSyncResult {
	result := ThreatIntelSyncResult{Source: "epss"}
	startTime := time.Now()

	// Get sync status
	status, err := s.repo.SyncStatus().GetBySource(ctx, "epss")
	if err != nil {
		result.Error = fmt.Errorf("failed to get sync status: %w", err)
		return result
	}

	if !status.IsEnabled() {
		result.Error = threatintel.ErrSyncDisabled
		return result
	}

	// Mark sync as started
	status.MarkSyncStarted()
	if err := s.repo.SyncStatus().Update(ctx, status); err != nil {
		s.logger.Error("failed to update sync status", "error", err)
	}

	s.logger.Info("starting EPSS sync")

	// Fetch and parse EPSS data
	scores, err := s.fetchEPSSData(ctx)
	if err != nil {
		result.Error = err
		status.MarkSyncFailed(err.Error())
		if updateErr := s.repo.SyncStatus().Update(ctx, status); updateErr != nil {
			s.logger.Error("failed to update sync status after error", "error", updateErr)
		}
		return result
	}

	// Batch upsert scores
	if err := s.repo.EPSS().UpsertBatch(ctx, scores); err != nil {
		result.Error = fmt.Errorf("failed to upsert EPSS scores: %w", err)
		status.MarkSyncFailed(err.Error())
		if updateErr := s.repo.SyncStatus().Update(ctx, status); updateErr != nil {
			s.logger.Error("failed to update sync status after error", "error", updateErr)
		}
		return result
	}

	duration := time.Since(startTime)
	result.RecordsSynced = len(scores)
	result.DurationMs = duration.Milliseconds()

	// Mark sync as successful
	status.MarkSyncSuccess(len(scores), int(duration.Milliseconds()))
	if err := s.repo.SyncStatus().Update(ctx, status); err != nil {
		s.logger.Error("failed to update sync status", "error", err)
	}

	s.logger.Info("EPSS sync completed",
		"records", len(scores),
		"duration_ms", duration.Milliseconds(),
	)

	return result
}

// SyncKEV syncs KEV catalog from CISA.
func (s *ThreatIntelService) SyncKEV(ctx context.Context) ThreatIntelSyncResult {
	result := ThreatIntelSyncResult{Source: "kev"}
	startTime := time.Now()

	// Get sync status
	status, err := s.repo.SyncStatus().GetBySource(ctx, "kev")
	if err != nil {
		result.Error = fmt.Errorf("failed to get sync status: %w", err)
		return result
	}

	if !status.IsEnabled() {
		result.Error = threatintel.ErrSyncDisabled
		return result
	}

	// Mark sync as started
	status.MarkSyncStarted()
	if err := s.repo.SyncStatus().Update(ctx, status); err != nil {
		s.logger.Error("failed to update sync status", "error", err)
	}

	s.logger.Info("starting KEV sync")

	// Fetch and parse KEV data
	entries, err := s.fetchKEVData(ctx)
	if err != nil {
		result.Error = err
		status.MarkSyncFailed(err.Error())
		if updateErr := s.repo.SyncStatus().Update(ctx, status); updateErr != nil {
			s.logger.Error("failed to update sync status after error", "error", updateErr)
		}
		return result
	}

	// Batch upsert in chunks to avoid memory issues
	chunkSize := 100
	for i := 0; i < len(entries); i += chunkSize {
		end := i + chunkSize
		if end > len(entries) {
			end = len(entries)
		}
		chunk := entries[i:end]
		if err := s.repo.KEV().UpsertBatch(ctx, chunk); err != nil {
			result.Error = fmt.Errorf("failed to upsert KEV entries: %w", err)
			status.MarkSyncFailed(err.Error())
			if updateErr := s.repo.SyncStatus().Update(ctx, status); updateErr != nil {
				s.logger.Error("failed to update sync status after error", "error", updateErr)
			}
			return result
		}
	}

	duration := time.Since(startTime)
	result.RecordsSynced = len(entries)
	result.DurationMs = duration.Milliseconds()

	// Mark sync as successful
	status.MarkSyncSuccess(len(entries), int(duration.Milliseconds()))
	if err := s.repo.SyncStatus().Update(ctx, status); err != nil {
		s.logger.Error("failed to update sync status", "error", err)
	}

	s.logger.Info("KEV sync completed",
		"records", len(entries),
		"duration_ms", duration.Milliseconds(),
	)

	return result
}

// fetchEPSSData fetches and parses EPSS data from FIRST.org.
func (s *ThreatIntelService) fetchEPSSData(ctx context.Context) ([]*threatintel.EPSSScore, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EPSS data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Decompress gzip
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Parse CSV
	csvReader := csv.NewReader(gzReader)

	// Read header - EPSS CSV has a comment line first, then header
	// First line is like: #model_version:v2023.03.01,score_date:2024-01-15
	firstLine, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read first line: %w", err)
	}

	var modelVersion string
	var scoreDate time.Time

	// Parse metadata from first line
	if len(firstLine) > 0 && strings.HasPrefix(firstLine[0], "#") {
		metadata := strings.TrimPrefix(firstLine[0], "#")
		for _, part := range strings.Split(metadata, ",") {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				switch kv[0] {
				case "model_version":
					modelVersion = kv[1]
				case "score_date":
					scoreDate, _ = time.Parse("2006-01-02", kv[1])
				}
			}
		}
	}

	if scoreDate.IsZero() {
		scoreDate = time.Now().UTC()
	}

	// Read actual header
	_, err = csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Parse records
	var scores []*threatintel.EPSSScore
	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read record: %w", err)
		}

		if len(record) < 3 {
			continue
		}

		cveID := record[0]
		if !strings.HasPrefix(cveID, "CVE-") {
			continue
		}

		epssScore, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			continue
		}

		percentile, err := strconv.ParseFloat(record[2], 64)
		if err != nil {
			percentile = 0
		}

		// EPSS percentile is 0-1, convert to 0-100
		percentile *= 100

		scores = append(scores, threatintel.NewEPSSScore(
			cveID,
			epssScore,
			percentile,
			modelVersion,
			scoreDate,
		))
	}

	return scores, nil
}

// fetchKEVData fetches and parses KEV data from CISA.
func (s *ThreatIntelService) fetchKEVData(ctx context.Context) ([]*threatintel.KEVEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KEV data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse JSON
	var kevCatalog kevCatalogResponse
	if err := json.NewDecoder(resp.Body).Decode(&kevCatalog); err != nil {
		return nil, fmt.Errorf("failed to parse KEV JSON: %w", err)
	}

	// Convert to domain entities
	entries := make([]*threatintel.KEVEntry, 0, len(kevCatalog.Vulnerabilities))
	for _, v := range kevCatalog.Vulnerabilities {
		dateAdded, _ := time.Parse("2006-01-02", v.DateAdded)
		dueDate, _ := time.Parse("2006-01-02", v.DueDate)

		// Parse CWEs if present
		var cwes []string
		if v.CWE != "" && v.CWE != "NVD-CWE-noinfo" {
			cwes = []string{v.CWE}
		}

		entries = append(entries, threatintel.NewKEVEntry(
			v.CVEID,
			v.VendorProject,
			v.Product,
			v.VulnerabilityName,
			v.ShortDescription,
			dateAdded,
			dueDate,
			v.KnownRansomwareCampaignUse,
			v.Notes,
			cwes,
		))
	}

	return entries, nil
}

// GetSyncStatuses returns all sync statuses.
func (s *ThreatIntelService) GetSyncStatuses(ctx context.Context) ([]*threatintel.SyncStatus, error) {
	return s.repo.SyncStatus().GetAll(ctx)
}

// GetSyncStatus returns sync status for a specific source.
func (s *ThreatIntelService) GetSyncStatus(ctx context.Context, source string) (*threatintel.SyncStatus, error) {
	return s.repo.SyncStatus().GetBySource(ctx, source)
}

// SetSyncEnabled enables or disables sync for a source.
func (s *ThreatIntelService) SetSyncEnabled(ctx context.Context, source string, enabled bool) error {
	status, err := s.repo.SyncStatus().GetBySource(ctx, source)
	if err != nil {
		return err
	}
	status.SetEnabled(enabled)
	return s.repo.SyncStatus().Update(ctx, status)
}

// EnrichCVEs enriches multiple CVEs with threat intel data.
func (s *ThreatIntelService) EnrichCVEs(ctx context.Context, cveIDs []string) (map[string]*threatintel.ThreatIntelEnrichment, error) {
	return s.repo.EnrichCVEs(ctx, cveIDs)
}

// EnrichCVE enriches a single CVE with threat intel data.
func (s *ThreatIntelService) EnrichCVE(ctx context.Context, cveID string) (*threatintel.ThreatIntelEnrichment, error) {
	return s.repo.EnrichCVE(ctx, cveID)
}

// GetEPSSScore retrieves an EPSS score by CVE ID.
func (s *ThreatIntelService) GetEPSSScore(ctx context.Context, cveID string) (*threatintel.EPSSScore, error) {
	return s.repo.EPSS().GetByCVEID(ctx, cveID)
}

// GetEPSSScores retrieves EPSS scores for multiple CVE IDs.
func (s *ThreatIntelService) GetEPSSScores(ctx context.Context, cveIDs []string) ([]*threatintel.EPSSScore, error) {
	return s.repo.EPSS().GetByCVEIDs(ctx, cveIDs)
}

// GetHighRiskEPSS retrieves high-risk EPSS scores.
func (s *ThreatIntelService) GetHighRiskEPSS(ctx context.Context, threshold float64, limit int) ([]*threatintel.EPSSScore, error) {
	return s.repo.EPSS().GetHighRisk(ctx, threshold, limit)
}

// GetKEVEntry retrieves a KEV entry by CVE ID.
func (s *ThreatIntelService) GetKEVEntry(ctx context.Context, cveID string) (*threatintel.KEVEntry, error) {
	return s.repo.KEV().GetByCVEID(ctx, cveID)
}

// IsInKEV checks if a CVE is in the KEV catalog.
func (s *ThreatIntelService) IsInKEV(ctx context.Context, cveID string) (bool, error) {
	return s.repo.KEV().ExistsByCVEID(ctx, cveID)
}

// GetKEVStats returns KEV statistics.
func (s *ThreatIntelService) GetKEVStats(ctx context.Context) (*KEVStats, error) {
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
func (s *ThreatIntelService) GetEPSSStats(ctx context.Context) (*EPSSStats, error) {
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

// GetThreatIntelStats returns unified threat intelligence statistics.
// This combines EPSS stats, KEV stats, and sync statuses in a single call.
func (s *ThreatIntelService) GetThreatIntelStats(ctx context.Context) (*ThreatIntelStats, error) {
	stats := &ThreatIntelStats{}

	// Get EPSS stats (continue even if error - partial data is OK)
	epssStats, err := s.GetEPSSStats(ctx)
	if err != nil {
		s.logger.Warn("failed to get EPSS stats", "error", err)
	} else {
		stats.EPSS = epssStats
	}

	// Get KEV stats
	kevStats, err := s.GetKEVStats(ctx)
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

			if status.LastSyncError() != "" {
				e := status.LastSyncError()
				dto.LastError = &e
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

// KEVStats contains KEV catalog statistics.
type KEVStats struct {
	TotalEntries            int `json:"total_entries"`
	PastDueCount            int `json:"past_due_count"`
	RecentlyAddedLast30Days int `json:"recently_added_last_30_days"`
	RansomwareRelatedCount  int `json:"ransomware_related_count"`
}

// EPSSStats contains EPSS statistics.
type EPSSStats struct {
	TotalScores       int `json:"total_scores"`
	HighRiskCount     int `json:"high_risk_count"`     // EPSS > 0.1 (10%)
	CriticalRiskCount int `json:"critical_risk_count"` // EPSS > 0.3 (30%)
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
	LastError      *string `json:"last_error,omitempty"`
	NextSyncAt     *string `json:"next_sync_at,omitempty"`
}

// kevCatalogResponse represents the CISA KEV JSON response.
type kevCatalogResponse struct {
	Title           string             `json:"title"`
	CatalogVersion  string             `json:"catalogVersion"`
	DateReleased    string             `json:"dateReleased"`
	Count           int                `json:"count"`
	Vulnerabilities []kevVulnerability `json:"vulnerabilities"`
}

type kevVulnerability struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	ShortDescription           string `json:"shortDescription"`
	DateAdded                  string `json:"dateAdded"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
	CWE                        string `json:"cwes,omitempty"`
}

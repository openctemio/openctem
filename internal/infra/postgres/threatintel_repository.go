package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatintel"
)

// ThreatIntelRepository implements threatintel.ThreatIntelRepository using PostgreSQL.
type ThreatIntelRepository struct {
	db         *DB
	epssRepo   *EPSSRepository
	kevRepo    *KEVRepository
	statusRepo *SyncStatusRepository
}

// NewThreatIntelRepository creates a new ThreatIntelRepository.
func NewThreatIntelRepository(db *DB) *ThreatIntelRepository {
	return &ThreatIntelRepository{
		db:         db,
		epssRepo:   &EPSSRepository{db: db},
		kevRepo:    &KEVRepository{db: db},
		statusRepo: &SyncStatusRepository{db: db},
	}
}

// EPSS returns the EPSS repository.
func (r *ThreatIntelRepository) EPSS() threatintel.EPSSRepository {
	return r.epssRepo
}

// KEV returns the KEV repository.
func (r *ThreatIntelRepository) KEV() threatintel.KEVRepository {
	return r.kevRepo
}

// SyncStatus returns the sync status repository.
func (r *ThreatIntelRepository) SyncStatus() threatintel.SyncStatusRepository {
	return r.statusRepo
}

// EnrichCVEs enriches multiple CVEs with threat intel data.
func (r *ThreatIntelRepository) EnrichCVEs(ctx context.Context, cveIDs []string) (map[string]*threatintel.ThreatIntelEnrichment, error) {
	if len(cveIDs) == 0 {
		return make(map[string]*threatintel.ThreatIntelEnrichment), nil
	}

	result := make(map[string]*threatintel.ThreatIntelEnrichment)
	for _, cveID := range cveIDs {
		result[cveID] = threatintel.NewThreatIntelEnrichment(cveID)
	}

	// Fetch EPSS scores
	epssScores, err := r.epssRepo.GetByCVEIDs(ctx, cveIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EPSS scores: %w", err)
	}
	for _, score := range epssScores {
		if enrichment, ok := result[score.CVEID()]; ok {
			enrichment.WithEPSS(score.Score(), score.Percentile())
		}
	}

	// Fetch KEV entries
	kevEntries, err := r.kevRepo.GetByCVEIDs(ctx, cveIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KEV entries: %w", err)
	}
	for _, entry := range kevEntries {
		if enrichment, ok := result[entry.CVEID()]; ok {
			dateAdded := entry.DateAdded().Format("2006-01-02")
			dueDate := entry.DueDate().Format("2006-01-02")
			ransomware := entry.KnownRansomwareCampaignUse()
			enrichment.WithKEV(dateAdded, dueDate, ransomware)
		}
	}

	return result, nil
}

// EnrichCVE enriches a single CVE with threat intel data.
func (r *ThreatIntelRepository) EnrichCVE(ctx context.Context, cveID string) (*threatintel.ThreatIntelEnrichment, error) {
	enrichments, err := r.EnrichCVEs(ctx, []string{cveID})
	if err != nil {
		return nil, err
	}
	return enrichments[cveID], nil
}

// =============================================================================
// EPSS Repository
// =============================================================================

// EPSSRepository implements threatintel.EPSSRepository.
type EPSSRepository struct {
	db *DB
}

// Upsert creates or updates an EPSS score.
func (r *EPSSRepository) Upsert(ctx context.Context, score *threatintel.EPSSScore) error {
	query := `
		INSERT INTO epss_scores (cve_id, epss_score, percentile, model_version, score_date, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (cve_id) DO UPDATE SET
			epss_score = EXCLUDED.epss_score,
			percentile = EXCLUDED.percentile,
			model_version = EXCLUDED.model_version,
			score_date = EXCLUDED.score_date,
			updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		score.CVEID(),
		score.Score(),
		score.Percentile(),
		score.ModelVersion(),
		score.ScoreDate(),
	)
	if err != nil {
		return fmt.Errorf("failed to upsert EPSS score: %w", err)
	}
	return nil
}

// UpsertBatch creates or updates multiple EPSS scores efficiently.
func (r *EPSSRepository) UpsertBatch(ctx context.Context, scores []*threatintel.EPSSScore) error {
	if len(scores) == 0 {
		return nil
	}

	// Use COPY for bulk insert with ON CONFLICT handling via temp table
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Create temp table
	_, err = tx.ExecContext(ctx, `
		CREATE TEMP TABLE temp_epss_scores (
			cve_id VARCHAR(30),
			epss_score DECIMAL(8,6),
			percentile DECIMAL(8,6),
			model_version VARCHAR(20),
			score_date DATE
		) ON COMMIT DROP
	`)
	if err != nil {
		return fmt.Errorf("failed to create temp table: %w", err)
	}

	// Prepare COPY statement
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("temp_epss_scores",
		"cve_id", "epss_score", "percentile", "model_version", "score_date"))
	if err != nil {
		return fmt.Errorf("failed to prepare COPY statement: %w", err)
	}
	defer stmt.Close()

	for _, score := range scores {
		_, err = stmt.ExecContext(ctx,
			score.CVEID(),
			score.Score(),
			score.Percentile(),
			score.ModelVersion(),
			score.ScoreDate(),
		)
		if err != nil {
			return fmt.Errorf("failed to copy row: %w", err)
		}
	}

	_, err = stmt.ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to flush COPY: %w", err)
	}

	// Upsert from temp table
	_, err = tx.ExecContext(ctx, `
		INSERT INTO epss_scores (cve_id, epss_score, percentile, model_version, score_date, updated_at)
		SELECT cve_id, epss_score, percentile, model_version, score_date, NOW()
		FROM temp_epss_scores
		ON CONFLICT (cve_id) DO UPDATE SET
			epss_score = EXCLUDED.epss_score,
			percentile = EXCLUDED.percentile,
			model_version = EXCLUDED.model_version,
			score_date = EXCLUDED.score_date,
			updated_at = NOW()
	`)
	if err != nil {
		return fmt.Errorf("failed to upsert from temp table: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetByCVEID retrieves an EPSS score by CVE ID.
func (r *EPSSRepository) GetByCVEID(ctx context.Context, cveID string) (*threatintel.EPSSScore, error) {
	query := `
		SELECT cve_id, epss_score, percentile, model_version, score_date, created_at, updated_at
		FROM epss_scores WHERE cve_id = $1
	`
	row := r.db.QueryRowContext(ctx, query, cveID)
	return r.scanEPSSScore(row)
}

// GetByCVEIDs retrieves EPSS scores for multiple CVE IDs.
func (r *EPSSRepository) GetByCVEIDs(ctx context.Context, cveIDs []string) ([]*threatintel.EPSSScore, error) {
	if len(cveIDs) == 0 {
		return []*threatintel.EPSSScore{}, nil
	}

	query := `
		SELECT cve_id, epss_score, percentile, model_version, score_date, created_at, updated_at
		FROM epss_scores WHERE cve_id = ANY($1)
	`
	rows, err := r.db.QueryContext(ctx, query, pq.Array(cveIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to query EPSS scores: %w", err)
	}
	defer rows.Close()

	return r.scanEPSSScores(rows)
}

// GetHighRisk retrieves all high-risk EPSS scores (score > threshold).
func (r *EPSSRepository) GetHighRisk(ctx context.Context, threshold float64, limit int) ([]*threatintel.EPSSScore, error) {
	query := `
		SELECT cve_id, epss_score, percentile, model_version, score_date, created_at, updated_at
		FROM epss_scores WHERE epss_score > $1
		ORDER BY epss_score DESC LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query high-risk EPSS scores: %w", err)
	}
	defer rows.Close()

	return r.scanEPSSScores(rows)
}

// GetTopPercentile retrieves scores in top N percentile.
func (r *EPSSRepository) GetTopPercentile(ctx context.Context, percentile float64, limit int) ([]*threatintel.EPSSScore, error) {
	threshold := 100.0 - percentile
	query := `
		SELECT cve_id, epss_score, percentile, model_version, score_date, created_at, updated_at
		FROM epss_scores WHERE percentile >= $1
		ORDER BY percentile DESC LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query top percentile EPSS scores: %w", err)
	}
	defer rows.Close()

	return r.scanEPSSScores(rows)
}

// Count returns the total number of EPSS scores.
func (r *EPSSRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM epss_scores").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count EPSS scores: %w", err)
	}
	return count, nil
}

// DeleteAll removes all EPSS scores.
func (r *EPSSRepository) DeleteAll(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "TRUNCATE TABLE epss_scores")
	if err != nil {
		return fmt.Errorf("failed to truncate EPSS scores: %w", err)
	}
	return nil
}

func (r *EPSSRepository) scanEPSSScore(row *sql.Row) (*threatintel.EPSSScore, error) {
	var (
		cveID        string
		epssScore    float64
		percentile   sql.NullFloat64
		modelVersion sql.NullString
		scoreDate    time.Time
		createdAt    time.Time
		updatedAt    time.Time
	)

	err := row.Scan(&cveID, &epssScore, &percentile, &modelVersion, &scoreDate, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, threatintel.ErrEPSSNotFound
		}
		return nil, fmt.Errorf("failed to scan EPSS score: %w", err)
	}

	return threatintel.ReconstituteEPSSScore(
		cveID,
		epssScore,
		percentile.Float64,
		modelVersion.String,
		scoreDate,
		createdAt,
		updatedAt,
	), nil
}

func (r *EPSSRepository) scanEPSSScores(rows *sql.Rows) ([]*threatintel.EPSSScore, error) {
	var scores []*threatintel.EPSSScore
	for rows.Next() {
		var (
			cveID        string
			epssScore    float64
			percentile   sql.NullFloat64
			modelVersion sql.NullString
			scoreDate    time.Time
			createdAt    time.Time
			updatedAt    time.Time
		)

		err := rows.Scan(&cveID, &epssScore, &percentile, &modelVersion, &scoreDate, &createdAt, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan EPSS score: %w", err)
		}

		scores = append(scores, threatintel.ReconstituteEPSSScore(
			cveID,
			epssScore,
			percentile.Float64,
			modelVersion.String,
			scoreDate,
			createdAt,
			updatedAt,
		))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating EPSS scores: %w", err)
	}

	return scores, nil
}

// =============================================================================
// KEV Repository
// =============================================================================

// KEVRepository implements threatintel.KEVRepository.
type KEVRepository struct {
	db *DB
}

// Upsert creates or updates a KEV entry.
func (r *KEVRepository) Upsert(ctx context.Context, entry *threatintel.KEVEntry) error {
	query := `
		INSERT INTO kev_catalog (cve_id, vendor_project, product, vulnerability_name, short_description,
			date_added, due_date, known_ransomware_campaign_use, notes, cwes, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		ON CONFLICT (cve_id) DO UPDATE SET
			vendor_project = EXCLUDED.vendor_project,
			product = EXCLUDED.product,
			vulnerability_name = EXCLUDED.vulnerability_name,
			short_description = EXCLUDED.short_description,
			due_date = EXCLUDED.due_date,
			known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
			notes = EXCLUDED.notes,
			cwes = EXCLUDED.cwes,
			updated_at = NOW()
	`
	dueDate := entry.DueDate()
	var dueDateNullTime sql.NullTime
	if !dueDate.IsZero() {
		dueDateNullTime = sql.NullTime{Time: dueDate, Valid: true}
	}
	_, err := r.db.ExecContext(ctx, query,
		entry.CVEID(),
		nullString(entry.VendorProject()),
		nullString(entry.Product()),
		entry.VulnerabilityName(),
		nullString(entry.ShortDescription()),
		entry.DateAdded(),
		dueDateNullTime,
		nullString(entry.KnownRansomwareCampaignUse()),
		nullString(entry.Notes()),
		pq.Array(entry.CWEs()),
	)
	if err != nil {
		return fmt.Errorf("failed to upsert KEV entry: %w", err)
	}
	return nil
}

// UpsertBatch creates or updates multiple KEV entries.
func (r *KEVRepository) UpsertBatch(ctx context.Context, entries []*threatintel.KEVEntry) error {
	if len(entries) == 0 {
		return nil
	}

	// Build bulk upsert query
	valueStrings := make([]string, 0, len(entries))
	valueArgs := make([]interface{}, 0, len(entries)*10)

	for i, entry := range entries {
		base := i * 10
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9, base+10,
		))

		dueDate := entry.DueDate()
		var dueDateNullTime sql.NullTime
		if !dueDate.IsZero() {
			dueDateNullTime = sql.NullTime{Time: dueDate, Valid: true}
		}
		valueArgs = append(valueArgs,
			entry.CVEID(),
			nullString(entry.VendorProject()),
			nullString(entry.Product()),
			entry.VulnerabilityName(),
			nullString(entry.ShortDescription()),
			entry.DateAdded(),
			dueDateNullTime,
			nullString(entry.KnownRansomwareCampaignUse()),
			nullString(entry.Notes()),
			pq.Array(entry.CWEs()),
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO kev_catalog (cve_id, vendor_project, product, vulnerability_name, short_description,
			date_added, due_date, known_ransomware_campaign_use, notes, cwes)
		VALUES %s
		ON CONFLICT (cve_id) DO UPDATE SET
			vendor_project = EXCLUDED.vendor_project,
			product = EXCLUDED.product,
			vulnerability_name = EXCLUDED.vulnerability_name,
			short_description = EXCLUDED.short_description,
			due_date = EXCLUDED.due_date,
			known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
			notes = EXCLUDED.notes,
			cwes = EXCLUDED.cwes,
			updated_at = NOW()
	`, strings.Join(valueStrings, ", "))

	_, err := r.db.ExecContext(ctx, query, valueArgs...)
	if err != nil {
		return fmt.Errorf("failed to upsert KEV entries: %w", err)
	}
	return nil
}

// GetByCVEID retrieves a KEV entry by CVE ID.
func (r *KEVRepository) GetByCVEID(ctx context.Context, cveID string) (*threatintel.KEVEntry, error) {
	query := `
		SELECT cve_id, vendor_project, product, vulnerability_name, short_description,
			date_added, due_date, known_ransomware_campaign_use, notes, cwes, created_at, updated_at
		FROM kev_catalog WHERE cve_id = $1
	`
	row := r.db.QueryRowContext(ctx, query, cveID)
	return r.scanKEVEntry(row)
}

// GetByCVEIDs retrieves KEV entries for multiple CVE IDs.
func (r *KEVRepository) GetByCVEIDs(ctx context.Context, cveIDs []string) ([]*threatintel.KEVEntry, error) {
	if len(cveIDs) == 0 {
		return []*threatintel.KEVEntry{}, nil
	}

	query := `
		SELECT cve_id, vendor_project, product, vulnerability_name, short_description,
			date_added, due_date, known_ransomware_campaign_use, notes, cwes, created_at, updated_at
		FROM kev_catalog WHERE cve_id = ANY($1)
	`
	rows, err := r.db.QueryContext(ctx, query, pq.Array(cveIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to query KEV entries: %w", err)
	}
	defer rows.Close()

	return r.scanKEVEntries(rows)
}

// ExistsByCVEID checks if a CVE is in KEV.
func (r *KEVRepository) ExistsByCVEID(ctx context.Context, cveID string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM kev_catalog WHERE cve_id = $1)", cveID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check KEV existence: %w", err)
	}
	return exists, nil
}

// ExistsByCVEIDs checks which CVEs are in KEV.
func (r *KEVRepository) ExistsByCVEIDs(ctx context.Context, cveIDs []string) (map[string]bool, error) {
	if len(cveIDs) == 0 {
		return make(map[string]bool), nil
	}

	query := `SELECT cve_id FROM kev_catalog WHERE cve_id = ANY($1)`
	rows, err := r.db.QueryContext(ctx, query, pq.Array(cveIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to query KEV CVE IDs: %w", err)
	}
	defer rows.Close()

	result := make(map[string]bool)
	for _, id := range cveIDs {
		result[id] = false
	}

	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			return nil, fmt.Errorf("failed to scan CVE ID: %w", err)
		}
		result[cveID] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating CVE IDs: %w", err)
	}

	return result, nil
}

// GetPastDue retrieves KEV entries past their due date.
func (r *KEVRepository) GetPastDue(ctx context.Context, limit int) ([]*threatintel.KEVEntry, error) {
	query := `
		SELECT cve_id, vendor_project, product, vulnerability_name, short_description,
			date_added, due_date, known_ransomware_campaign_use, notes, cwes, created_at, updated_at
		FROM kev_catalog
		WHERE due_date IS NOT NULL AND due_date < NOW()
		ORDER BY due_date ASC LIMIT $1
	`
	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query past due KEV entries: %w", err)
	}
	defer rows.Close()

	return r.scanKEVEntries(rows)
}

// GetRecentlyAdded retrieves recently added KEV entries.
func (r *KEVRepository) GetRecentlyAdded(ctx context.Context, days, limit int) ([]*threatintel.KEVEntry, error) {
	query := `
		SELECT cve_id, vendor_project, product, vulnerability_name, short_description,
			date_added, due_date, known_ransomware_campaign_use, notes, cwes, created_at, updated_at
		FROM kev_catalog
		WHERE date_added >= NOW() - INTERVAL '1 day' * $1
		ORDER BY date_added DESC LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, days, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recently added KEV entries: %w", err)
	}
	defer rows.Close()

	return r.scanKEVEntries(rows)
}

// GetRansomwareRelated retrieves KEV entries with known ransomware use.
func (r *KEVRepository) GetRansomwareRelated(ctx context.Context, limit int) ([]*threatintel.KEVEntry, error) {
	query := `
		SELECT cve_id, vendor_project, product, vulnerability_name, short_description,
			date_added, due_date, known_ransomware_campaign_use, notes, cwes, created_at, updated_at
		FROM kev_catalog
		WHERE known_ransomware_campaign_use IS NOT NULL AND known_ransomware_campaign_use != 'Unknown'
		ORDER BY date_added DESC LIMIT $1
	`
	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query ransomware-related KEV entries: %w", err)
	}
	defer rows.Close()

	return r.scanKEVEntries(rows)
}

// Count returns the total number of KEV entries.
func (r *KEVRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM kev_catalog").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count KEV entries: %w", err)
	}
	return count, nil
}

// DeleteAll removes all KEV entries.
func (r *KEVRepository) DeleteAll(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "TRUNCATE TABLE kev_catalog")
	if err != nil {
		return fmt.Errorf("failed to truncate KEV catalog: %w", err)
	}
	return nil
}

func (r *KEVRepository) scanKEVEntry(row *sql.Row) (*threatintel.KEVEntry, error) {
	var (
		cveID             string
		vendorProject     sql.NullString
		product           sql.NullString
		vulnerabilityName string
		shortDescription  sql.NullString
		dateAdded         time.Time
		dueDate           sql.NullTime
		ransomwareUse     sql.NullString
		notes             sql.NullString
		cwes              pq.StringArray
		createdAt         time.Time
		updatedAt         time.Time
	)

	err := row.Scan(&cveID, &vendorProject, &product, &vulnerabilityName, &shortDescription,
		&dateAdded, &dueDate, &ransomwareUse, &notes, &cwes, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, threatintel.ErrKEVNotFound
		}
		return nil, fmt.Errorf("failed to scan KEV entry: %w", err)
	}

	return threatintel.ReconstituteKEVEntry(
		cveID,
		vendorProject.String,
		product.String,
		vulnerabilityName,
		shortDescription.String,
		dateAdded,
		dueDate.Time,
		ransomwareUse.String,
		notes.String,
		[]string(cwes),
		createdAt,
		updatedAt,
	), nil
}

func (r *KEVRepository) scanKEVEntries(rows *sql.Rows) ([]*threatintel.KEVEntry, error) {
	var entries []*threatintel.KEVEntry
	for rows.Next() {
		var (
			cveID             string
			vendorProject     sql.NullString
			product           sql.NullString
			vulnerabilityName string
			shortDescription  sql.NullString
			dateAdded         time.Time
			dueDate           sql.NullTime
			ransomwareUse     sql.NullString
			notes             sql.NullString
			cwes              pq.StringArray
			createdAt         time.Time
			updatedAt         time.Time
		)

		err := rows.Scan(&cveID, &vendorProject, &product, &vulnerabilityName, &shortDescription,
			&dateAdded, &dueDate, &ransomwareUse, &notes, &cwes, &createdAt, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan KEV entry: %w", err)
		}

		entries = append(entries, threatintel.ReconstituteKEVEntry(
			cveID,
			vendorProject.String,
			product.String,
			vulnerabilityName,
			shortDescription.String,
			dateAdded,
			dueDate.Time,
			ransomwareUse.String,
			notes.String,
			[]string(cwes),
			createdAt,
			updatedAt,
		))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating KEV entries: %w", err)
	}

	return entries, nil
}

// =============================================================================
// Sync Status Repository
// =============================================================================

// SyncStatusRepository implements threatintel.SyncStatusRepository.
type SyncStatusRepository struct {
	db *DB
}

// GetBySource retrieves sync status by source name.
func (r *SyncStatusRepository) GetBySource(ctx context.Context, source string) (*threatintel.SyncStatus, error) {
	query := `
		SELECT id, source_name, last_sync_at, last_sync_status, last_sync_error,
			records_synced, sync_duration_ms, next_sync_at, sync_interval_hours,
			is_enabled, metadata, created_at, updated_at
		FROM threat_intel_sync_status WHERE source_name = $1
	`
	row := r.db.QueryRowContext(ctx, query, source)
	return r.scanSyncStatus(row)
}

// GetAll retrieves all sync statuses.
func (r *SyncStatusRepository) GetAll(ctx context.Context) ([]*threatintel.SyncStatus, error) {
	query := `
		SELECT id, source_name, last_sync_at, last_sync_status, last_sync_error,
			records_synced, sync_duration_ms, next_sync_at, sync_interval_hours,
			is_enabled, metadata, created_at, updated_at
		FROM threat_intel_sync_status ORDER BY source_name
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query sync statuses: %w", err)
	}
	defer rows.Close()

	return r.scanSyncStatuses(rows)
}

// GetEnabled retrieves enabled sync statuses.
func (r *SyncStatusRepository) GetEnabled(ctx context.Context) ([]*threatintel.SyncStatus, error) {
	query := `
		SELECT id, source_name, last_sync_at, last_sync_status, last_sync_error,
			records_synced, sync_duration_ms, next_sync_at, sync_interval_hours,
			is_enabled, metadata, created_at, updated_at
		FROM threat_intel_sync_status WHERE is_enabled = TRUE ORDER BY source_name
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query enabled sync statuses: %w", err)
	}
	defer rows.Close()

	return r.scanSyncStatuses(rows)
}

// GetDueForSync retrieves sources due for sync.
func (r *SyncStatusRepository) GetDueForSync(ctx context.Context) ([]*threatintel.SyncStatus, error) {
	query := `
		SELECT id, source_name, last_sync_at, last_sync_status, last_sync_error,
			records_synced, sync_duration_ms, next_sync_at, sync_interval_hours,
			is_enabled, metadata, created_at, updated_at
		FROM threat_intel_sync_status
		WHERE is_enabled = TRUE
		AND (next_sync_at IS NULL OR next_sync_at <= NOW())
		AND last_sync_status != 'running'
		ORDER BY source_name
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query due for sync statuses: %w", err)
	}
	defer rows.Close()

	return r.scanSyncStatuses(rows)
}

// Update updates a sync status.
func (r *SyncStatusRepository) Update(ctx context.Context, status *threatintel.SyncStatus) error {
	metadataJSON, err := json.Marshal(status.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE threat_intel_sync_status SET
			last_sync_at = $2, last_sync_status = $3, last_sync_error = $4,
			records_synced = $5, sync_duration_ms = $6, next_sync_at = $7,
			sync_interval_hours = $8, is_enabled = $9, metadata = $10, updated_at = NOW()
		WHERE id = $1
	`
	_, err = r.db.ExecContext(ctx, query,
		status.ID().String(),
		status.LastSyncAt(),
		status.LastSyncStatus().String(),
		nullString(status.LastSyncError()),
		status.RecordsSynced(),
		status.SyncDurationMs(),
		status.NextSyncAt(),
		status.SyncIntervalHours(),
		status.IsEnabled(),
		metadataJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to update sync status: %w", err)
	}
	return nil
}

func (r *SyncStatusRepository) scanSyncStatus(row *sql.Row) (*threatintel.SyncStatus, error) {
	var (
		id                string
		sourceName        string
		lastSyncAt        sql.NullTime
		lastSyncStatus    string
		lastSyncError     sql.NullString
		recordsSynced     int
		syncDurationMs    sql.NullInt64
		nextSyncAt        sql.NullTime
		syncIntervalHours int
		isEnabled         bool
		metadataJSON      []byte
		createdAt         time.Time
		updatedAt         time.Time
	)

	err := row.Scan(&id, &sourceName, &lastSyncAt, &lastSyncStatus, &lastSyncError,
		&recordsSynced, &syncDurationMs, &nextSyncAt, &syncIntervalHours,
		&isEnabled, &metadataJSON, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, threatintel.ErrSyncStatusNotFound
		}
		return nil, fmt.Errorf("failed to scan sync status: %w", err)
	}

	var lastSyncTime *time.Time
	if lastSyncAt.Valid {
		lastSyncTime = &lastSyncAt.Time
	}

	var nextSyncTime *time.Time
	if nextSyncAt.Valid {
		nextSyncTime = &nextSyncAt.Time
	}

	syncState, _ := threatintel.ParseSyncState(lastSyncStatus)

	var durationMs int
	if syncDurationMs.Valid {
		durationMs = int(syncDurationMs.Int64)
	}

	var metadata map[string]any
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}
	if metadata == nil {
		metadata = make(map[string]any)
	}

	return threatintel.ReconstituteSyncStatus(
		shared.MustIDFromString(id),
		sourceName,
		lastSyncTime,
		syncState,
		lastSyncError.String,
		recordsSynced,
		durationMs,
		nextSyncTime,
		syncIntervalHours,
		isEnabled,
		metadata,
		createdAt,
		updatedAt,
	), nil
}

func (r *SyncStatusRepository) scanSyncStatuses(rows *sql.Rows) ([]*threatintel.SyncStatus, error) {
	var statuses []*threatintel.SyncStatus
	for rows.Next() {
		var (
			id                string
			sourceName        string
			lastSyncAt        sql.NullTime
			lastSyncStatus    string
			lastSyncError     sql.NullString
			recordsSynced     int
			syncDurationMs    sql.NullInt64
			nextSyncAt        sql.NullTime
			syncIntervalHours int
			isEnabled         bool
			metadataJSON      []byte
			createdAt         time.Time
			updatedAt         time.Time
		)

		err := rows.Scan(&id, &sourceName, &lastSyncAt, &lastSyncStatus, &lastSyncError,
			&recordsSynced, &syncDurationMs, &nextSyncAt, &syncIntervalHours,
			&isEnabled, &metadataJSON, &createdAt, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan sync status: %w", err)
		}

		var lastSyncTime *time.Time
		if lastSyncAt.Valid {
			lastSyncTime = &lastSyncAt.Time
		}

		var nextSyncTime *time.Time
		if nextSyncAt.Valid {
			nextSyncTime = &nextSyncAt.Time
		}

		syncState, _ := threatintel.ParseSyncState(lastSyncStatus)

		var durationMs int
		if syncDurationMs.Valid {
			durationMs = int(syncDurationMs.Int64)
		}

		var metadata map[string]any
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}
		if metadata == nil {
			metadata = make(map[string]any)
		}

		statuses = append(statuses, threatintel.ReconstituteSyncStatus(
			shared.MustIDFromString(id),
			sourceName,
			lastSyncTime,
			syncState,
			lastSyncError.String,
			recordsSynced,
			durationMs,
			nextSyncTime,
			syncIntervalHours,
			isEnabled,
			metadata,
			createdAt,
			updatedAt,
		))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating sync statuses: %w", err)
	}

	return statuses, nil
}

// Note: nullTime helper is already defined in helpers.go

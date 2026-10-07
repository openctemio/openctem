package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMSummaryRepository answers the EASM overview (RFC-036 §6.10
// GET /easm/summary) with a handful of aggregate queries. Every query is
// tenant-scoped; a non-nil data scope narrows asset-bound rows to the
// caller's assets (user_accessible_assets), exactly as the asset list does.
type EASMSummaryRepository struct {
	db *DB
}

var _ easm.SummaryReader = (*EASMSummaryRepository)(nil)

// NewEASMSummaryRepository creates the repository.
func NewEASMSummaryRepository(db *DB) *EASMSummaryRepository {
	return &EASMSummaryRepository{db: db}
}

// EASMSurfaceTypes are the asset types the overview counts as the external
// surface (asset category external_surface).
var EASMSurfaceTypes = []string{"domain", "subdomain", "ip_address", "certificate"}

// EASMExposureTypes are the exposure event types EASM produces: only types
// something writes today, so the summary never counts a category no check
// can fill (research/22 P0-13, 22b I7). api_exposed, bucket_public,
// header_missing, dns_change, port_closed, service_changed and
// subdomain_removed come back when they have a producer.
var EASMExposureTypes = []string{
	"subdomain_discovered", "certificate_expiring", "certificate_expired",
	"port_open", "service_detected", "ssl_issue",
	"dangling_cname", "dangling_ns", "email_security_weak", "subdomain_takeover",
}

// notRejected excludes assets a person marked as not the tenant's: they stay
// in the attribution counts but are not part of the surface, its new-asset
// windows or its exposures.
const notRejected = ` AND NOT EXISTS (SELECT 1 FROM asset_attributions rj WHERE rj.asset_id = %s AND rj.state = 'rejected')`

func notRejectedFor(col string) string { return fmt.Sprintf(notRejected, col) }

// inInventory keeps assets in the inventory (RFC-054 §4.4,
// attribution.InInventory): not in the review queue and not rejected.
const inInventory = ` AND NOT EXISTS (SELECT 1 FROM asset_attributions iv WHERE iv.asset_id = %s AND iv.state IN ('needs_review', 'candidate', 'rejected'))`

// InInventorySQL is the inventory-membership condition for an asset id column.
func InInventorySQL(col string) string { return fmt.Sprintf(inInventory, col) }

// scopeClause returns the SQL that narrows an asset id column to the data
// scope, with its args appended; empty when the caller is unrestricted.
func scopeClause(col string, scopeUserID *shared.ID, tenantID shared.ID, args []any) (string, []any) {
	if scopeUserID == nil {
		return "", args
	}
	args = append(args, scopeUserID.String(), tenantID.String())
	return fmt.Sprintf(" AND %s IN (SELECT asset_id FROM user_accessible_assets WHERE user_id = $%d AND tenant_id = $%d)",
		col, len(args)-1, len(args)), args
}

// Summary computes the overview. scopeUserID nil = unrestricted.
func (r *EASMSummaryRepository) Summary(ctx context.Context, tenantID shared.ID, scopeUserID *shared.ID, now time.Time, topN int) (*easm.SummaryData, error) {
	out := &easm.SummaryData{
		AssetsByType: map[string]int{}, AttributionByState: map[string]int{},
		OpenBySeverity: map[string]int{}, OpenByType: map[string]int{},
	}
	tid := tenantID.String()

	if err := r.surfaceCounts(ctx, tenantID, scopeUserID, out); err != nil {
		return nil, err
	}

	// Review queue age, internet-facing services, new assets.
	var oldest sql.NullTime
	args := []any{tid}
	sc, args := scopeClause("aa.asset_id", scopeUserID, tenantID, args)
	if err := r.db.QueryRowContext(ctx, `
		SELECT min(aa.created_at) FROM asset_attributions aa
		WHERE aa.tenant_id = $1 AND aa.state = 'needs_review'`+sc, args...).Scan(&oldest); err != nil {
		return nil, fmt.Errorf("easm review age: %w", err)
	}
	out.OldestReviewSince = nullTimeValue(oldest)

	// The review queue by the rule that put each asset there.
	byReason, err := r.reviewByReason(ctx, tenantID, scopeUserID)
	if err != nil {
		return nil, err
	}
	out.ReviewByReason = byReason

	args = []any{tid}
	sc, args = scopeClause("a.id", scopeUserID, tenantID, args)
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM assets a
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.asset_type = 'service' AND a.is_internet_accessible AND a.status <> 'archived'`+InInventorySQL("a.id")+sc,
		args...).Scan(&out.ExposedServices); err != nil {
		return nil, fmt.Errorf("easm exposed services: %w", err)
	}

	var cycle sql.NullTime
	if err := r.db.QueryRowContext(ctx, `
		SELECT max(activated_at) FROM ctem_cycles WHERE tenant_id = $1 AND activated_at IS NOT NULL`, tid).Scan(&cycle); err != nil {
		return nil, fmt.Errorf("easm cycle start: %w", err)
	}
	out.CycleStart = nullTimeValue(cycle)
	cycleFrom := now.Add(100 * 365 * 24 * time.Hour) // no cycle: count nothing
	if out.CycleStart != nil {
		cycleFrom = *out.CycleStart
	}
	args = []any{tid, pq.Array(EASMSurfaceTypes), now.Add(-7 * 24 * time.Hour), now.Add(-30 * 24 * time.Hour), cycleFrom}
	sc, args = scopeClause("a.id", scopeUserID, tenantID, args)
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE a.first_seen >= $3),
		       count(*) FILTER (WHERE a.first_seen >= $4),
		       count(*) FILTER (WHERE a.first_seen >= $5)
		FROM assets a
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.asset_type = ANY($2) AND a.status <> 'archived'`+InInventorySQL("a.id")+sc,
		args...).Scan(&out.NewSince7d, &out.NewSince30d, &out.NewSinceCycle); err != nil {
		return nil, fmt.Errorf("easm new assets: %w", err)
	}

	if err := r.exposureCounts(ctx, tenantID, scopeUserID, out); err != nil {
		return nil, err
	}
	risks, err := r.topRisks(ctx, tenantID, scopeUserID, topN)
	if err != nil {
		return nil, err
	}
	out.TopRisks = risks

	// CT monitoring freshness (tenant-level; not asset-bound).
	var oldestOK sql.NullTime
	err = r.db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE consecutive_failures > 0),
		       count(*) FILTER (WHERE last_success_at IS NULL),
		       min(last_success_at)
		FROM ct_monitor_state WHERE tenant_id = $1`, tid).Scan(&out.CTWatched, &out.CTFailing, &out.CTNeverSucceeded, &oldestOK)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("easm ct freshness: %w", err)
	}
	out.CTOldestSuccess = nullTimeValue(oldestOK)
	return out, nil
}

// reviewByReason counts the review queue (needs_review, candidate) by the
// rule that set each record, narrowed to the data scope.
func (r *EASMSummaryRepository) reviewByReason(ctx context.Context, tenantID shared.ID, scopeUserID *shared.ID) (map[string]int, error) {
	args := []any{tenantID.String()}
	sc, args := scopeClause("aa.asset_id", scopeUserID, tenantID, args)
	rows, err := r.db.QueryContext(ctx, `
		SELECT aa.reason, count(*) FROM asset_attributions aa
		JOIN assets a ON a.id = aa.asset_id AND a.tenant_id = aa.tenant_id AND a.deleted_at IS NULL
		WHERE aa.tenant_id = $1 AND aa.state IN ('needs_review', 'candidate')`+sc+`
		GROUP BY 1`, args...)
	if err != nil {
		return nil, fmt.Errorf("easm review by reason: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var reason string
		var n int
		if err := rows.Scan(&reason, &n); err != nil {
			return nil, err
		}
		out[reason] = n
	}
	return out, rows.Err()
}

// surfaceCounts fills the surface by type and attribution state.
func (r *EASMSummaryRepository) surfaceCounts(ctx context.Context, tenantID shared.ID, scopeUserID *shared.ID, out *easm.SummaryData) error {
	args := []any{tenantID.String(), pq.Array(EASMSurfaceTypes)}
	sc, args := scopeClause("a.id", scopeUserID, tenantID, args)
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.asset_type, COALESCE(aa.state, ''), count(*)
		FROM assets a
		LEFT JOIN asset_attributions aa ON aa.asset_id = a.id
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.asset_type = ANY($2) AND a.status <> 'archived'`+sc+`
		GROUP BY 1, 2`, args...)
	if err != nil {
		return fmt.Errorf("easm surface counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ, state string
		var n int
		if err := rows.Scan(&typ, &state, &n); err != nil {
			return err
		}
		if attribution.InInventory(attribution.State(state)) {
			out.AssetsByType[typ] += n
		}
		out.AttributionByState[state] += n
	}
	return rows.Err()
}

// exposureCounts fills the open external exposures by severity and type.
func (r *EASMSummaryRepository) exposureCounts(ctx context.Context, tenantID shared.ID, scopeUserID *shared.ID, out *easm.SummaryData) error {
	args := []any{tenantID.String(), pq.Array(EASMExposureTypes)}
	sc, args := scopeClause("e.asset_id", scopeUserID, tenantID, args)
	rows, err := r.db.QueryContext(ctx, `
		SELECT e.severity, e.event_type, count(*)
		FROM exposure_events e
		WHERE e.tenant_id = $1 AND e.state = 'active' AND e.event_type = ANY($2)
		  AND `+notOfDeletedAssetSQL("e.asset_id")+notRejectedFor("e.asset_id")+sc+`
		GROUP BY 1, 2`, args...)
	if err != nil {
		return fmt.Errorf("easm exposures: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sev, typ string
		var n int
		if err := rows.Scan(&sev, &typ, &n); err != nil {
			return err
		}
		out.OpenBySeverity[sev] += n
		out.OpenByType[typ] += n
	}
	return rows.Err()
}

// topRisks lists the most severe open external exposures (medium and up).
func (r *EASMSummaryRepository) topRisks(ctx context.Context, tenantID shared.ID, scopeUserID *shared.ID, topN int) ([]easm.RiskRow, error) {
	args := []any{tenantID.String(), pq.Array(EASMExposureTypes), topN}
	sc, args := scopeClause("e.asset_id", scopeUserID, tenantID, args)
	rows, err := r.db.QueryContext(ctx, `
		SELECT e.id, e.event_type, e.severity, e.title, e.asset_id, a.name, e.last_seen_at
		FROM exposure_events e
		LEFT JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
		WHERE e.tenant_id = $1 AND e.state = 'active' AND e.event_type = ANY($2)
		  AND e.severity IN ('critical', 'high', 'medium')
		  AND (a.id IS NULL OR a.deleted_at IS NULL)`+notRejectedFor("e.asset_id")+sc+`
		ORDER BY CASE e.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, e.last_seen_at DESC
		LIMIT $3`, args...)
	if err != nil {
		return nil, fmt.Errorf("easm top risks: %w", err)
	}
	defer rows.Close()
	var out []easm.RiskRow
	for rows.Next() {
		var rk easm.RiskRow
		var assetID, assetName sql.NullString
		if err := rows.Scan(&rk.ID, &rk.Type, &rk.Severity, &rk.Title, &assetID, &assetName, &rk.LastSeen); err != nil {
			return nil, err
		}
		if assetID.Valid {
			rk.AssetID = &assetID.String
		}
		if assetName.Valid {
			rk.AssetName = &assetName.String
		}
		out = append(out, rk)
	}
	return out, rows.Err()
}

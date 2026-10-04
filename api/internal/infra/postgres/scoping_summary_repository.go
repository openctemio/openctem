package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scoping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopingSummaryRepository computes the Scoping overview in one query.
//
// Definitions (tenant-wide; no data scope, like the Program Health
// scorecards):
//   - assets: status <> 'archived'. Crown jewels are such assets with
//     is_crown_jewel. A crown jewel has an owner when an asset_owners row
//     names a user or group of the tenant (the same test as the inventory's
//     has_owner facet; asset_owners is the only owner store).
//   - assets.in_business_unit: assets with a business_unit_assets row for one
//     of the tenant's units. Group-level business units are not counted.
//   - business_services.with_assets: services with a business_service_assets
//     row whose asset belongs to the tenant.
//   - boundary: every scope target and exclusion, whatever its status (the
//     totals of GET /scope/stats).
//   - threat_models.crown_jewels_covered: distinct current crown jewels that a
//     crown_jewel-scoped threat model points at.
//   - active cycle: status active, else the newest review, else the newest
//     planning cycle. Charter counts are JSON array lengths.
type ScopingSummaryRepository struct {
	db *DB
}

// NewScopingSummaryRepository creates the repository.
func NewScopingSummaryRepository(db *DB) *ScopingSummaryRepository {
	return &ScopingSummaryRepository{db: db}
}

var _ scoping.SummaryReader = (*ScopingSummaryRepository)(nil)

const scopingSummaryQuery = `
WITH live_assets AS (
	SELECT a.id, a.is_crown_jewel
	  FROM assets a
	 WHERE a.tenant_id = $1 AND a.status <> 'archived'
),
crown AS (
	SELECT la.id FROM live_assets la WHERE la.is_crown_jewel
),
focus AS (
	SELECT c.id, c.name, c.status, c.start_date, c.end_date, c.charter
	  FROM ctem_cycles c
	 WHERE c.tenant_id = $1 AND c.status IN ('active', 'review', 'planning')
	 ORDER BY CASE c.status WHEN 'active' THEN 0 WHEN 'review' THEN 1 ELSE 2 END,
	          c.created_at DESC
	 LIMIT 1
)
SELECT
	(SELECT COUNT(*) FROM crown),
	(SELECT COUNT(*) FROM crown cj
	  WHERE EXISTS (
	        SELECT 1 FROM asset_owners ao
	         WHERE ao.asset_id = cj.id
	           AND (ao.group_id IS NULL OR ao.group_id IN (SELECT id FROM groups WHERE tenant_id = $1))
	           AND (ao.user_id  IS NULL OR ao.user_id  IN (SELECT user_id FROM tenant_members WHERE tenant_id = $1)))),
	(SELECT COUNT(*) FROM business_services bs WHERE bs.tenant_id = $1),
	(SELECT COUNT(*) FROM business_services bs
	  WHERE bs.tenant_id = $1
	    AND EXISTS (SELECT 1 FROM business_service_assets bsa
	                  JOIN assets a ON a.id = bsa.asset_id AND a.tenant_id = $1
	                 WHERE bsa.service_id = bs.id)),
	(SELECT COUNT(*) FROM business_units bu WHERE bu.tenant_id = $1),
	(SELECT COUNT(*) FROM live_assets),
	(SELECT COUNT(*) FROM live_assets la
	  WHERE EXISTS (SELECT 1 FROM business_unit_assets bua
	                  JOIN business_units bu ON bu.id = bua.business_unit_id AND bu.tenant_id = $1
	                 WHERE bua.asset_id = la.id)),
	(SELECT COUNT(*) FROM scope_targets st WHERE st.tenant_id = $1),
	(SELECT COUNT(*) FROM scope_exclusions se WHERE se.tenant_id = $1),
	(SELECT COUNT(*) FROM attacker_profiles ap WHERE ap.tenant_id = $1),
	(SELECT COUNT(*) FROM threat_models tm WHERE tm.tenant_id = $1),
	(SELECT COUNT(DISTINCT cj.id) FROM threat_models tm
	   JOIN crown cj ON cj.id = tm.scope_ref_id
	  WHERE tm.tenant_id = $1 AND tm.scope_type = 'crown_jewel'),
	(SELECT COUNT(*) FROM ctem_cycles c WHERE c.tenant_id = $1),
	f.id::text, f.name, f.status, f.start_date, f.end_date,
	CASE WHEN jsonb_typeof(f.charter->'objectives') = 'array' THEN jsonb_array_length(f.charter->'objectives') END,
	CASE WHEN jsonb_typeof(f.charter->'success_criteria') = 'array' THEN jsonb_array_length(f.charter->'success_criteria') END,
	CASE WHEN jsonb_typeof(f.charter->'in_scope_services') = 'array' THEN jsonb_array_length(f.charter->'in_scope_services') END,
	CASE WHEN jsonb_typeof(f.charter->'exclusions') = 'array' THEN jsonb_array_length(f.charter->'exclusions') END,
	CASE WHEN jsonb_typeof(f.charter->'threat_scenarios') = 'array' THEN jsonb_array_length(f.charter->'threat_scenarios') END,
	(SELECT COUNT(*) FROM ctem_cycle_scope_snapshots s WHERE s.cycle_id = f.id),
	(SELECT COUNT(*) FROM ctem_cycle_attacker_profiles cap
	   JOIN attacker_profiles ap ON ap.id = cap.profile_id AND ap.tenant_id = $1
	  WHERE cap.cycle_id = f.id)
FROM (SELECT 1) one
LEFT JOIN focus f ON TRUE
`

// GetSummary returns the Scoping overview for a tenant.
func (r *ScopingSummaryRepository) GetSummary(ctx context.Context, tenantID shared.ID) (*scoping.Summary, error) {
	var (
		s                                        scoping.Summary
		cycleID, cycleName, cycleStatus          sql.NullString
		startDate, endDate                       sql.NullTime
		objectives, criteria, services, excl, ts sql.NullInt64
		scopeAssets, cycleProfiles               sql.NullInt64
	)
	err := r.db.QueryRowContext(ctx, scopingSummaryQuery, tenantID.String()).Scan(
		&s.CrownJewels.Total, &s.CrownJewels.WithOwner,
		&s.BusinessServices.Total, &s.BusinessServices.WithAssets,
		&s.BusinessUnits.Total,
		&s.Assets.Total, &s.Assets.InBusinessUnit,
		&s.Boundary.Targets, &s.Boundary.Exclusions,
		&s.AttackerProfiles.Total,
		&s.ThreatModels.Total, &s.ThreatModels.CrownJewelsCovered,
		&s.Cycles.Total,
		&cycleID, &cycleName, &cycleStatus, &startDate, &endDate,
		&objectives, &criteria, &services, &excl, &ts,
		&scopeAssets, &cycleProfiles,
	)
	if err != nil {
		return nil, fmt.Errorf("scoping summary: %w", err)
	}
	if cycleID.Valid {
		s.ActiveCycle = &scoping.CycleSummary{
			ID:               cycleID.String,
			Name:             cycleName.String,
			Status:           cycleStatus.String,
			StartDate:        nullDate(startDate),
			EndDate:          nullDate(endDate),
			Objectives:       int(objectives.Int64),
			SuccessCriteria:  int(criteria.Int64),
			InScopeServices:  int(services.Int64),
			Exclusions:       int(excl.Int64),
			ThreatScenarios:  int(ts.Int64),
			ScopeAssets:      int(scopeAssets.Int64),
			AttackerProfiles: int(cycleProfiles.Int64),
		}
	}
	return &s, nil
}

func nullDate(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

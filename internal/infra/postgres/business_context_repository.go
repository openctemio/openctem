package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/openctemio/api/internal/app/finding"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// BusinessContextLookupRepo resolves per-asset business-unit and
// business-service criticality for business-aligned prioritization. It
// implements finding.BusinessContextLookup with three batch, tenant-scoped
// queries (BU membership, business-service membership, and control-plane
// propagation) and reduces each to the MAX criticality per asset in Go — no
// per-asset query.
type BusinessContextLookupRepo struct {
	db *sql.DB
}

// NewBusinessContextLookupRepo creates a new lookup adapter.
func NewBusinessContextLookupRepo(db *sql.DB) *BusinessContextLookupRepo {
	return &BusinessContextLookupRepo{db: db}
}

var _ finding.BusinessContextLookup = (*BusinessContextLookupRepo)(nil)

// GetForAssets returns, for each asset, the MAX business-unit criticality and
// the MAX business-service criticality (with the source name), keyed by asset
// ID. Assets that belong to no BU and power no service are absent from the map.
// Both queries are tenant-scoped.
func (r *BusinessContextLookupRepo) GetForAssets(
	ctx context.Context,
	tenantID shared.ID,
	assetIDs []shared.ID,
) (map[shared.ID]finding.AssetBusinessContext, error) {
	result := make(map[shared.ID]finding.AssetBusinessContext)
	if len(assetIDs) == 0 {
		return result, nil
	}

	idStrings := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		idStrings[i] = id.String()
	}

	// Pass 1: business-unit criticality (an asset may belong to several BUs;
	// reduce to the most critical).
	buQuery := `
		SELECT bua.asset_id, bu.criticality, bu.name
		FROM business_unit_assets bua
		JOIN business_units bu
		  ON bu.id = bua.business_unit_id AND bu.tenant_id = bua.tenant_id
		WHERE bua.tenant_id = $1
		  AND bua.asset_id = ANY($2)
	`
	if err := r.reduceMaxCriticality(ctx, buQuery, tenantID, idStrings, result, applyBU); err != nil {
		return nil, fmt.Errorf("business unit criticality lookup: %w", err)
	}

	// Pass 2: business-service criticality (an asset may power several services;
	// reduce to the most critical).
	svcQuery := `
		SELECT bsa.asset_id, bs.criticality, bs.name
		FROM business_service_assets bsa
		JOIN business_services bs
		  ON bs.id = bsa.service_id AND bs.tenant_id = bsa.tenant_id
		WHERE bsa.tenant_id = $1
		  AND bsa.asset_id = ANY($2)
	`
	if err := r.reduceMaxCriticality(ctx, svcQuery, tenantID, idStrings, result, applyService); err != nil {
		return nil, fmt.Errorf("business service criticality lookup: %w", err)
	}

	// Pass 3: control-plane propagation. An asset marked as the control plane of
	// another (is_control_plane edge) is itself as critical as what it serves —
	// compromising it pulls in the served asset. Per the #467 data model the
	// control-plane asset is the TARGET of the edge and the served asset is the
	// SOURCE (e.g. service --depends_on--> IdP, is_control_plane=true: the IdP is
	// the control plane). So for each asset in the set, find the inbound
	// is_control_plane edges and fold in the MAX criticality of the SOURCE
	// (served) assets. Only ever raises (floor). Direction note: per-relationship-
	// type normalization (manages/monitors put the control plane on the source)
	// is a follow-up; today we key off the depends_on-style target endpoint.
	cpQuery := `
		SELECT ar.target_asset_id, sa.criticality, sa.name
		FROM asset_relationships ar
		JOIN assets sa
		  ON sa.id = ar.source_asset_id AND sa.tenant_id = ar.tenant_id
		WHERE ar.tenant_id = $1
		  AND ar.is_control_plane = TRUE
		  AND ar.target_asset_id = ANY($2)
	`
	if err := r.reduceMaxCriticality(ctx, cpQuery, tenantID, idStrings, result, applyControlPlane); err != nil {
		return nil, fmt.Errorf("control-plane criticality lookup: %w", err)
	}

	return result, nil
}

// criticalityApplier folds one (criticality, name) membership row into an asset's
// business context, updating the relevant leg when the row is more critical than
// what is already recorded. Each pass (BU, service, control-plane) supplies its
// own applier so reduceMaxCriticality stays generic.
type criticalityApplier func(bctx *finding.AssetBusinessContext, crit asset.Criticality, name string)

func applyBU(bctx *finding.AssetBusinessContext, crit asset.Criticality, name string) {
	if crit.Score() > bctx.BusinessUnitCriticality.Score() {
		bctx.BusinessUnitCriticality = crit
		bctx.BusinessUnitName = name
	}
}

func applyService(bctx *finding.AssetBusinessContext, crit asset.Criticality, name string) {
	if crit.Score() > bctx.BusinessServiceCriticality.Score() {
		bctx.BusinessServiceCriticality = crit
		bctx.BusinessServiceName = name
	}
}

func applyControlPlane(bctx *finding.AssetBusinessContext, crit asset.Criticality, name string) {
	if crit.Score() > bctx.ControlPlaneServesCriticality.Score() {
		bctx.ControlPlaneServesCriticality = crit
		bctx.ControlPlaneServesName = name
	}
}

// reduceMaxCriticality runs a membership query returning (asset_id, criticality,
// name) rows and folds the MAX criticality per asset into result via the supplied
// applier (which decides WHICH leg — BU, service, or control-plane — the row
// contributes to).
func (r *BusinessContextLookupRepo) reduceMaxCriticality(
	ctx context.Context,
	query string,
	tenantID shared.ID,
	idStrings []string,
	result map[shared.ID]finding.AssetBusinessContext,
	apply criticalityApplier,
) error {
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(idStrings))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var aidStr, critStr, name string
		if err := rows.Scan(&aidStr, &critStr, &name); err != nil {
			continue
		}
		aid, err := shared.IDFromString(aidStr)
		if err != nil {
			continue
		}
		crit := asset.Criticality(critStr)

		bctx := result[aid]
		apply(&bctx, crit, name)
		result[aid] = bctx
	}
	return rows.Err()
}

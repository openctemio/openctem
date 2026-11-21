package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/domain/webendpoint"
)

// The reads behind one origin's path tree (docs/architecture/web-surface.md,
// "Path tree"): every statement carries the tenant and the origin asset id;
// the service checks the caller's data scope on the origin first.

const webPathReadTimeout = 3 * time.Second

// OriginName returns the name of a live asset of the tenant.
func (r *WebEndpointRepository) OriginName(ctx context.Context, tenantID, assetID shared.ID) (string, error) {
	var name string
	err := r.db.QueryRowContext(ctx, `SELECT name FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
		tenantID.String(), assetID.String()).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", shared.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("origin name: %w", err)
	}
	return name, nil
}

// OriginEndpoints returns at most limit endpoint rows of one origin of the
// tenant (idx_web_endpoints_origin), ordered by path template, and whether
// the origin holds more.
func (r *WebEndpointRepository) OriginEndpoints(ctx context.Context, tenantID, assetID shared.ID, limit int) ([]*webendpoint.Endpoint, bool, error) {
	tx, err := beginRead(ctx, r.db.DB, webPathReadTimeout)
	if err != nil {
		return nil, false, fmt.Errorf("begin path read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, "SELECT "+webEndpointColumns+webEndpointFrom+
		" WHERE e.tenant_id = $1 AND e.origin_asset_id = $2 ORDER BY e.path_template, e.method LIMIT $3",
		tenantID.String(), assetID.String(), limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("origin endpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*webendpoint.Endpoint, 0, 256)
	for rows.Next() {
		e, err := scanWebEndpoint(rows)
		if err != nil {
			return nil, false, fmt.Errorf("scan origin endpoint: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("origin endpoints: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit path read: %w", err)
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

// openOnAsset is the open-finding predicate the asset's own count uses:
// open status, not held for proof, not branch-only. Domain constants only,
// never input.
//
//nolint:gosec // G202: fixed SQL fragments of the domain, no input
var openOnAsset = `f.tenant_id = $1 AND f.asset_id = $2 AND NOT f.branch_only AND ` +
	vulnerability.OpenStatusSQL("f.status") + ` AND ` + vulnerability.NotHeldSQL("f.verification_state")

// openFindingsByLocation groups the open findings of one asset by location
// key and severity (idx_findings_tenant_asset_status).
//
//nolint:gosec // G202: fixed SQL fragments and numbered placeholders only
var openFindingsByLocation = `SELECT COALESCE(f.location_key, ''), f.severity, COUNT(*), COALESCE(e.path_template, ''), COALESCE(e.method, '')
	FROM findings f` + findingEndpointJoin + ` WHERE ` + openOnAsset + ` GROUP BY 1, 2, 4, 5 LIMIT $3`

// findingEndpointJoin links a finding to the endpoint of its web location,
// when the endpoint belongs to the same tenant and the same origin asset
// (finding_web_locations, PK tenant_id + finding_id).
const findingEndpointJoin = ` LEFT JOIN finding_web_locations w ON w.tenant_id = f.tenant_id AND w.finding_id = f.id
	LEFT JOIN web_endpoints e ON e.tenant_id = w.tenant_id AND e.id = w.endpoint_id AND e.origin_asset_id = f.asset_id`

// OriginOpenFindings groups the origin asset's open findings by location key
// and severity.
func (r *WebEndpointRepository) OriginOpenFindings(ctx context.Context, tenantID, assetID shared.ID) ([]webendpoint.PathFinding, error) {
	tx, err := beginRead(ctx, r.db.DB, webPathReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("begin path findings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, openFindingsByLocation, tenantID.String(), assetID.String(), webendpoint.MaxPathFindingRows)
	if err != nil {
		return nil, fmt.Errorf("origin findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]webendpoint.PathFinding, 0, 32)
	for rows.Next() {
		var f webendpoint.PathFinding
		if err := rows.Scan(&f.LocationKey, &f.Severity, &f.Count, &f.Template, &f.Method); err != nil {
			return nil, fmt.Errorf("scan origin finding: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("origin findings: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit path findings: %w", err)
	}
	return out, nil
}

// openURLFindings lists the asset's open findings with a URL location or a
// link to an endpoint.
//
//nolint:gosec // G202: fixed SQL fragments and numbered placeholders only
var openURLFindings = `SELECT f.id::text, COALESCE(NULLIF(f.title, ''), f.message), f.severity, f.status, COALESCE(f.location_key, ''),
	COALESCE(e.path_template, ''), COALESCE(e.method, '') FROM findings f` + findingEndpointJoin + ` WHERE ` +
	openOnAsset + ` AND (f.location_key LIKE 'url:%' OR e.id IS NOT NULL) ORDER BY f.id LIMIT $3`

// OriginURLFindings returns the origin asset's open findings with a URL
// location (titles bounded by the column), at most MaxPathFindingRows.
func (r *WebEndpointRepository) OriginURLFindings(ctx context.Context, tenantID, assetID shared.ID) ([]webendpoint.FindingRow, error) {
	tx, err := beginRead(ctx, r.db.DB, webPathReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("begin node findings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, openURLFindings, tenantID.String(), assetID.String(), webendpoint.MaxPathFindingRows)
	if err != nil {
		return nil, fmt.Errorf("node findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]webendpoint.FindingRow, 0, 16)
	for rows.Next() {
		var f webendpoint.FindingRow
		if err := rows.Scan(&f.ID, &f.Title, &f.Severity, &f.Status, &f.LocationKey, &f.Template, &f.Method); err != nil {
			return nil, fmt.Errorf("scan node finding: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("node findings: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit node findings: %w", err)
	}
	return out, nil
}

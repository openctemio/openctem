package postgres

// Inventory reads behind a scan's dynamic target selectors (RFC-068): the
// names a wildcard domain covers and the addresses inside a CIDR, as they
// are when a run starts. Every query is pinned to one tenant; the dispatch
// gate then decides each asset like a group member.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanSelectorRepository lists the assets a selector covers.
type ScanSelectorRepository struct {
	db *DB
}

// NewScanSelectorRepository creates the repository.
func NewScanSelectorRepository(db *DB) *ScanSelectorRepository {
	return &ScanSelectorRepository{db: db}
}

// maxSelectorRows bounds one read whatever the caller asks.
const maxSelectorRows = 20000

// ListSelectorAssets returns at most q.Limit assets of q.TenantID that the
// selector covers, freshest first (last_seen descending), so a cap keeps the
// names seen most recently. Archived and deleted assets are never returned;
// stale and inactive ones only with IncludeStale.
func (r *ScanSelectorRepository) ListSelectorAssets(ctx context.Context, q scan.SelectorQuery) ([]*assetgroup.ScanMember, error) {
	if q.TenantID.IsZero() {
		return nil, fmt.Errorf("%w: selector query needs a tenant", shared.ErrValidation)
	}
	limit := q.Limit
	if limit <= 0 || limit > maxSelectorRows {
		limit = maxSelectorRows
	}
	statuses := []string{"active"}
	if q.IncludeStale {
		statuses = append(statuses, "stale", "inactive")
	}
	args := []any{q.TenantID.String(), pq.Array(statuses)}
	var match string
	switch {
	case q.UnderDomain != "":
		root := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(q.UnderDomain), "."))
		if root == "" || strings.ContainsAny(root, "*%_\\ ") {
			return nil, fmt.Errorf("%w: invalid selector root %q", shared.ErrValidation, q.UnderDomain)
		}
		args = append(args, root, "%."+escapeLikePattern(root))
		match = `a.asset_class = 'domain' AND (lower(a.name) = $3 OR a.name ILIKE $4 ESCAPE '\')`
	case q.InCIDR != "":
		p, err := netip.ParsePrefix(strings.TrimSpace(q.InCIDR))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid selector range %q", shared.ErrValidation, q.InCIDR)
		}
		args = append(args, p.Masked().String())
		match = `a.asset_type IN ('ip_address', 'host') AND position('/' IN a.name) = 0
		  AND pg_input_is_valid(a.name, 'inet') AND a.name::inet <<= $3::inet`
	default:
		return nil, fmt.Errorf("%w: selector query needs a domain or a range", shared.ErrValidation)
	}
	seen := ""
	if q.SeenSince != nil {
		args = append(args, *q.SeenSince)
		seen = fmt.Sprintf(" AND a.last_seen >= $%d", len(args))
	}
	args = append(args, limit)

	//nolint:gosec // G202: match, seen and scanMemberMatchProps are fixed SQL with numbered placeholders
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, COALESCE(a.sub_type, ''), a.status, `+scanMemberMatchProps+`
		FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.status = ANY($2)
		  AND `+match+seen+`
		ORDER BY a.last_seen DESC NULLS LAST, a.name, a.id
		LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list selector assets: %w", err)
	}
	defer rows.Close()

	out := make([]*assetgroup.ScanMember, 0, 64)
	for rows.Next() {
		var (
			id, name, assetType, subType, status string
			props                                []byte
		)
		if err := rows.Scan(&id, &name, &assetType, &subType, &status, &props); err != nil {
			return nil, fmt.Errorf("scan selector asset: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			return nil, fmt.Errorf("selector asset id: %w", err)
		}
		m := &assetgroup.ScanMember{ID: aid, Name: name, Type: assetType, SubType: subType, Status: status}
		if len(props) > 0 {
			if err := json.Unmarshal(props, &m.Properties); err != nil {
				return nil, fmt.Errorf("selector asset %s properties: %w", id, err)
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

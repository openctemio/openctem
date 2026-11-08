package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetlist"
)

// assetListTimeout bounds one list or count statement: a filter that
// cannot finish in time is a 503 QUERY_TIMEOUT.
const assetListTimeout = "5s"

var errUncompiledAssetFilter = errors.New("asset filter was not compiled for the assets registry")

// assetTimeout maps a statement timeout to asset.ErrQueryTimeout.
func assetTimeout(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "57014" {
		return fmt.Errorf("%w: %w", asset.ErrQueryTimeout, err)
	}
	return err
}

// assetKeysetOrder is the keyset order of WhereQuery.Keyset; the index
// idx_assets_tenant_last_seen serves it per tenant.
const assetKeysetOrder = "a.last_seen DESC, a.id DESC"

// ListWhere lists one page of the assets a compiled filter matches (the
// list query contract). The filter starts with the caller's tenant and data
// scope; soft-deleted assets never match. The total is exact up to
// asset.CountCap and capped above it, so a count never reads the whole
// tenant.
func (r *AssetRepository) ListWhere(ctx context.Context, q asset.WhereQuery) (asset.WhereResult, error) {
	// Defense in depth: a WHERE that does not start with the tenant
	// predicate did not come from filterspec.Compile.
	if q.Where == nil || !strings.HasPrefix(q.Where.SQL, assetlist.Fields.TenantSQL+" = $") || q.Where.OrderBy == "" {
		return asset.WhereResult{}, errUncompiledAssetFilter
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return asset.WhereResult{}, fmt.Errorf("begin asset list: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+assetListTimeout+"'"); err != nil {
		return asset.WhereResult{}, fmt.Errorf("set asset list timeout: %w", err)
	}
	perPage := q.PerPage
	if perPage <= 0 {
		perPage = 20
	}
	page := max(q.Page, 1)
	where := liveAssetSQL("a") + " AND " + q.Where.SQL
	args := append([]any{}, q.Where.Args...)
	next := q.Where.NextArg
	if cond, propArgs := propertiesCondition(q.Properties, next); cond != "" {
		where += " AND " + cond
		args = append(args, propArgs...)
		next += len(propArgs)
	}

	//nolint:gosec // G202: the WHERE is compiled from registry constants; every value is bound
	countSQL := fmt.Sprintf("SELECT count(*) FROM (SELECT 1 FROM assets a WHERE %s LIMIT %d) c", where, asset.CountCap+1)
	var total int64
	if err := tx.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return asset.WhereResult{}, assetTimeout(fmt.Errorf("count assets: %w", err))
	}
	capped := total > asset.CountCap
	if capped {
		total = asset.CountCap
	}

	listWhere, listArgs, order, offset := where, args, q.Where.OrderBy, (page-1)*perPage
	if q.Keyset {
		order, offset = assetKeysetOrder, 0
		if q.After != nil {
			listWhere += fmt.Sprintf(" AND (a.last_seen, a.id) < ($%d::timestamptz, $%d::uuid)", next, next+1)
			listArgs = append(listArgs, q.After.LastSeen, q.After.ID.String())
		}
	}
	//nolint:gosec // G202: as above
	query := r.selectQuery() + " WHERE " + listWhere + " ORDER BY " + order + fmt.Sprintf(" LIMIT %d OFFSET %d", perPage, offset)
	rows, err := tx.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return asset.WhereResult{}, assetTimeout(fmt.Errorf("list assets: %w", err))
	}
	defer func() { _ = rows.Close() }()
	data := make([]*asset.Asset, 0, perPage)
	for rows.Next() {
		a, err := r.scanAssetFromRows(rows)
		if err != nil {
			return asset.WhereResult{}, err
		}
		data = append(data, a)
	}
	if err := rows.Err(); err != nil {
		return asset.WhereResult{}, assetTimeout(fmt.Errorf("list assets: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return asset.WhereResult{}, fmt.Errorf("commit asset list: %w", err)
	}
	res := asset.WhereResult{Data: data, Total: total, Capped: capped, Page: page, PerPage: perPage}
	res.TotalPages = int((total + int64(perPage) - 1) / int64(perPage))
	if q.Keyset && len(data) == perPage {
		last := data[len(data)-1]
		res.NextCursor = asset.Cursor{LastSeen: last.LastSeen(), ID: last.ID()}.Encode()
	}
	return res, nil
}

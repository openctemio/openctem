package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/technology"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TechnologyReadRepository reads the Technologies view: asset technologies
// grouped by name and version. Every read takes a filter compiled through
// the list query contract, so the tenant and the caller's data scope are
// always in the WHERE of the row stage, before anything is grouped.
type TechnologyReadRepository struct {
	db *DB
}

// NewTechnologyReadRepository creates the repository.
func NewTechnologyReadRepository(db *DB) *TechnologyReadRepository {
	return &TechnologyReadRepository{db: db}
}

const (
	technologyListTimeout  = "3s"
	technologyStatsTimeout = "2s"
)

var errUncompiledTechnologyFilter = errors.New("technology filter was not compiled for a tenant")

func checkTechnologyWhere(w *filterspec.Where) error {
	if w == nil || !strings.HasPrefix(w.SQL, technology.Fields.TenantSQL+" = $") || w.OrderBy == "" {
		return errUncompiledTechnologyFilter
	}
	return nil
}

// technologyGroups is the group stage for a compiled filter, aliased g. The
// filter is registry constants and bound placeholders only.
func technologyGroups(w *filterspec.Where) string {
	return "(" + technology.GroupSelectSQL + technology.RowsFromSQL + " WHERE " + w.SQL + technology.GroupBySQL + ") g"
}

const technologyColumns = `g.name_key, g.name, g.version, g.category, COALESCE(g.vendor, ''), COALESCE(g.cpe, ''), g.sources,
	g.asset_count, c.cve_count, COALESCE(c.top_cve, ''), c.top_cvss, c.kev, c.exploit, al.active_alerts,
	g.first_seen, g.last_seen`

// readOnlyTx opens a read-only transaction with a statement timeout.
func (r *TechnologyReadRepository) readOnlyTx(ctx context.Context, timeout string) (*sql.Tx, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin technology read: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+timeout+"'"); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set technology read timeout: %w", err)
	}
	return tx, nil
}

// ListWhere lists one page of technology versions matching a compiled
// filter, with the total, in one read-only transaction.
func (r *TechnologyReadRepository) ListWhere(
	ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*technology.Version], error) {
	var empty pagination.Result[*technology.Version]
	if err := checkTechnologyWhere(w); err != nil {
		return empty, err
	}
	tx, err := r.readOnlyTx(ctx, technologyListTimeout)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+technologyGroups(w), w.Args...).Scan(&total); err != nil {
		return empty, fmt.Errorf("count technologies: %w", err)
	}
	q := fmt.Sprintf("SELECT %s FROM %s%s ORDER BY %s LIMIT %d OFFSET %d", //nolint:gosec // G201: compiled filter
		technologyColumns, technologyGroups(w), technology.FiguresSQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("list technologies: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*technology.Version, 0, page.Limit())
	for rows.Next() {
		var (
			v       technology.Version
			sources pq.StringArray
			cvss    sql.NullFloat64
		)
		if err := rows.Scan(&v.Key, &v.Name, &v.Version, &v.Category, &v.Vendor, &v.CPE, &sources,
			&v.AssetCount, &v.CVECount, &v.TopCVE, &cvss, &v.KEV, &v.Exploit, &v.ActiveAlerts,
			&v.FirstSeen, &v.LastSeen); err != nil {
			return empty, fmt.Errorf("scan technology: %w", err)
		}
		v.Sources = []string(sources)
		if cvss.Valid {
			f := cvss.Float64
			v.TopCVSS = &f
		}
		out = append(out, &v)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list technologies: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit technology list: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// StatsWhere counts the technology versions of a compiled filter: the same
// WHERE as the list.
func (r *TechnologyReadRepository) StatsWhere(ctx context.Context, w *filterspec.Where) (*technology.Stats, error) {
	if err := checkTechnologyWhere(w); err != nil {
		return nil, err
	}
	tx, err := r.readOnlyTx(ctx, technologyStatsTimeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	q := `SELECT count(*), count(*) FILTER (WHERE c.cve_count > 0), count(*) FILTER (WHERE c.kev),
		count(*) FILTER (WHERE g.version = ''), count(*) FILTER (WHERE al.active_alerts > 0)
		FROM ` + technologyGroups(w) + technology.FiguresSQL //nolint:gosec // G202: compiled filter
	st := &technology.Stats{}
	if err := tx.QueryRowContext(ctx, q, w.Args...).Scan(&st.Total, &st.WithCVEs, &st.KEV,
		&st.UnknownVersion, &st.WithAlerts); err != nil {
		return nil, fmt.Errorf("technology stats: %w", err)
	}
	return st, tx.Commit()
}

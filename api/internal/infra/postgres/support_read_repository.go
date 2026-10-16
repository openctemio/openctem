package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/supportaccess"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// SupportReadRepository is the read model a support session sees
// (docs/rfcs/RFC-063-support-access.md): explicit allow-listed columns,
// always scoped to the grant's tenant, never the assets of a private program
// (support is no program member) or their findings. Read-only: no statement
// here writes.
type SupportReadRepository struct {
	db *DB
}

// NewSupportReadRepository creates the repository.
func NewSupportReadRepository(db *DB) *SupportReadRepository {
	return &SupportReadRepository{db: db}
}

var _ supportaccess.ReadRepository = (*SupportReadRepository)(nil)

// supportViewer is the user the private-program filter checks: the nil id is
// no program's member, so every private program's assets stay hidden.
var supportViewer = shared.ID{}

func supportNotHidden(assetExpr string) string {
	return filterspec.NotHiddenForViewer(assetExpr, "$1", supportViewer)
}

func supportOpenStatuses() pq.StringArray {
	st := vulnerability.OpenStatuses()
	out := make(pq.StringArray, 0, len(st))
	for _, s := range st {
		out = append(out, string(s))
	}
	return out
}

func supportLimit(q supportaccess.ListQuery) (int, int) {
	limit, offset := q.Limit, q.Offset
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	if offset < 0 || offset > 100000 {
		offset = 0
	}
	return limit, offset
}

// Overview counts the organization's assets and open findings.
func (r *SupportReadRepository) Overview(ctx context.Context, tenantID shared.ID) (*supportaccess.Overview, error) {
	o := &supportaccess.Overview{OpenFindingsBySeverity: map[string]int64{}}
	if err := r.db.QueryRowContext(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID.String()).Scan(&o.TenantName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, supportaccess.ErrNotFound
		}
		return nil, fmt.Errorf("support overview: %w", err)
	}
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND `+supportNotHidden("a.id"),
		tenantID.String()).Scan(&o.AssetCount); err != nil {
		return nil, fmt.Errorf("support overview assets: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT lower(f.severity), count(*) FROM findings f
		WHERE f.tenant_id = $1 AND f.status = ANY($2) AND `+supportNotHidden("f.asset_id")+`
		GROUP BY lower(f.severity)`, tenantID.String(), supportOpenStatuses())
	if err != nil {
		return nil, fmt.Errorf("support overview findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var sev string
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		o.OpenFindingsBySeverity[sev] = n
		o.OpenFindingCount += n
	}
	return o, rows.Err()
}

const supportFindingColumns = `
	f.id, COALESCE(NULLIF(f.title, ''), f.rule_name, ''), COALESCE(f.severity, ''), COALESCE(f.status, ''), COALESCE(f.source, ''),
	COALESCE(f.tool_name, ''), COALESCE(f.rule_id, ''), COALESCE(f.cve_id, ''), COALESCE(f.cwe_ids, '{}'),
	COALESCE(f.asset_id::text, ''), COALESCE(a.name, ''), COALESCE(a.asset_type, ''),
	COALESCE(f.file_path, ''), COALESCE(f.start_line, 0), COALESCE(f.sla_status, ''),
	f.first_detected_at, f.last_seen_at`

func scanSupportFinding(row interface{ Scan(...any) error }) (supportaccess.FindingView, error) {
	var (
		v               supportaccess.FindingView
		cwe             pq.StringArray
		first, lastSeen sql.NullTime
	)
	err := row.Scan(&v.ID, &v.Title, &v.Severity, &v.Status, &v.Source, &v.ToolName, &v.RuleID, &v.CVEID, &cwe,
		&v.AssetID, &v.AssetName, &v.AssetType, &v.FilePath, &v.StartLine, &v.SLAStatus, &first, &lastSeen)
	v.CWEIDs = []string(cwe)
	v.FirstDetectedAt = supportTimePtr(first)
	v.LastSeenAt = supportTimePtr(lastSeen)
	return v, err
}

func supportTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// ListFindings pages the organization's findings, worst first.
func (r *SupportReadRepository) ListFindings(ctx context.Context, tenantID shared.ID, q supportaccess.ListQuery) ([]supportaccess.FindingView, int64, error) {
	where := []string{"f.tenant_id = $1", supportNotHidden("f.asset_id")}
	args := []any{tenantID.String()}
	if s := strings.TrimSpace(q.Search); s != "" {
		args = append(args, "%"+filterspec.EscapeLike(s)+"%")
		where = append(where, fmt.Sprintf(`COALESCE(f.title, '') ILIKE $%d ESCAPE '\'`, len(args)))
	}
	if s := strings.TrimSpace(q.Severity); s != "" {
		args = append(args, strings.ToLower(s))
		where = append(where, fmt.Sprintf("lower(f.severity) = $%d", len(args)))
	}
	switch s := strings.TrimSpace(q.Status); s {
	case "":
	case "open":
		args = append(args, supportOpenStatuses())
		where = append(where, fmt.Sprintf("f.status = ANY($%d)", len(args)))
	default:
		args = append(args, s)
		where = append(where, fmt.Sprintf("f.status = $%d", len(args)))
	}
	cond := strings.Join(where, " AND ")
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings f WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("support findings count: %w", err)
	}
	limit, offset := supportLimit(q)
	args = append(args, limit, offset)
	rows, err := r.db.QueryContext(ctx, `SELECT `+supportFindingColumns+`
		FROM findings f LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE `+cond+fmt.Sprintf(`
		ORDER BY CASE lower(f.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		         f.last_seen_at DESC NULLS LAST, f.id
		LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("support findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]supportaccess.FindingView, 0, limit)
	for rows.Next() {
		v, err := scanSupportFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// GetFinding returns one finding of the organization.
func (r *SupportReadRepository) GetFinding(ctx context.Context, tenantID, id shared.ID) (*supportaccess.FindingView, error) {
	v, err := scanSupportFinding(r.db.QueryRowContext(ctx, `SELECT `+supportFindingColumns+`
		FROM findings f LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.id = $2 AND `+supportNotHidden("f.asset_id"), tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, supportaccess.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("support finding: %w", err)
	}
	return &v, nil
}

const supportAssetColumns = `
	a.id, a.name, COALESCE(a.asset_type, ''), COALESCE(a.criticality, ''), COALESCE(a.status, ''),
	COALESCE(a.exposure, ''), COALESCE(a.risk_score, 0),
	(SELECT count(*) FROM findings f WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id),
	a.first_seen, a.last_seen`

func scanSupportAsset(row interface{ Scan(...any) error }) (supportaccess.AssetView, error) {
	var (
		v           supportaccess.AssetView
		first, last sql.NullTime
	)
	err := row.Scan(&v.ID, &v.Name, &v.Type, &v.Criticality, &v.Status, &v.Exposure, &v.RiskScore, &v.FindingCount, &first, &last)
	v.FirstSeen, v.LastSeen = supportTimePtr(first), supportTimePtr(last)
	return v, err
}

// ListAssets pages the organization's assets, riskiest first.
func (r *SupportReadRepository) ListAssets(ctx context.Context, tenantID shared.ID, q supportaccess.ListQuery) ([]supportaccess.AssetView, int64, error) {
	where := []string{"a.tenant_id = $1", "a.deleted_at IS NULL", supportNotHidden("a.id")}
	args := []any{tenantID.String()}
	if s := strings.TrimSpace(q.Search); s != "" {
		args = append(args, "%"+filterspec.EscapeLike(s)+"%")
		where = append(where, fmt.Sprintf(`a.name ILIKE $%d ESCAPE '\'`, len(args)))
	}
	if s := strings.TrimSpace(q.Status); s != "" {
		args = append(args, s)
		where = append(where, fmt.Sprintf("a.status = $%d", len(args)))
	}
	cond := strings.Join(where, " AND ")
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("support assets count: %w", err)
	}
	limit, offset := supportLimit(q)
	args = append(args, limit, offset)
	rows, err := r.db.QueryContext(ctx, `SELECT `+supportAssetColumns+` FROM assets a WHERE `+cond+
		fmt.Sprintf(` ORDER BY a.risk_score DESC NULLS LAST, a.name, a.id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("support assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]supportaccess.AssetView, 0, limit)
	for rows.Next() {
		v, err := scanSupportAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// GetAsset returns one asset of the organization.
func (r *SupportReadRepository) GetAsset(ctx context.Context, tenantID, id shared.ID) (*supportaccess.AssetView, error) {
	v, err := scanSupportAsset(r.db.QueryRowContext(ctx, `SELECT `+supportAssetColumns+` FROM assets a
		WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL AND `+supportNotHidden("a.id"),
		tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, supportaccess.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("support asset: %w", err)
	}
	return &v, nil
}

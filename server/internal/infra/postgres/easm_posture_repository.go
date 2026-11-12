package postgres

// Attack surface posture facts and state (docs/architecture/easm-posture.md).
// A rebuild recomputes one organization's per-asset points in one
// transaction from the published findings facts (F1, dash_asset_state) and
// the active exposure events; reads sum the facts through a filter compiled
// for the caller, so the tenant and the data scope are always in the WHERE.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/posture"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// EASMPostureRepository implements posture.Repository.
type EASMPostureRepository struct {
	db *DB
}

var _ posture.Repository = (*EASMPostureRepository)(nil)

// NewEASMPostureRepository creates the repository.
func NewEASMPostureRepository(db *DB) *EASMPostureRepository {
	return &EASMPostureRepository{db: db}
}

const (
	postureRebuildTimeout = 2 * time.Minute
	postureReadTimeout    = 5 * time.Second
	postureInsertChunk    = 2000
	// postureBridgedSources are exposure events projected from findings
	// (secret and misconfiguration scans): the finding already counts.
	postureBridgedSources = "'secret_scan', 'misconfig_scan'"
)

// postureColumns are the point and issue columns in posture.Categories order.
var (
	posturePointCols = [posture.NumCategories]string{"vuln_points", "hijack_points", "service_points", "storage_points", "misconfig_points", "suspicious_points"}
	postureIssueCols = [posture.NumCategories]string{"vuln_issues", "hijack_issues", "service_issues", "storage_issues", "misconfig_issues", "suspicious_issues"}
)

// severityPointsSQL is a CASE giving posture.SeverityPoints for col.
func severityPointsSQL(col string) string {
	sevs := make([]string, 0, len(posture.SeverityPoints))
	for s := range posture.SeverityPoints {
		sevs = append(sevs, s)
	}
	sort.Strings(sevs)
	var b strings.Builder
	b.WriteString("(CASE " + col)
	for _, s := range sevs {
		fmt.Fprintf(&b, " WHEN '%s' THEN %g", s, posture.SeverityPoints[s])
	}
	b.WriteString(" ELSE 0 END)::numeric")
	return b.String()
}

// exposureCategorySQL is a CASE mapping e.event_type to its category index.
func exposureCategorySQL() (string, []string) {
	var b strings.Builder
	var all []string
	b.WriteString("(CASE")
	types := posture.ExposureTypes()
	for i, c := range posture.Categories() {
		ts := types[c]
		if len(ts) == 0 {
			continue
		}
		all = append(all, ts...)
		fmt.Fprintf(&b, " WHEN e.event_type IN ('%s') THEN %d", strings.Join(ts, "', '"), i)
	}
	b.WriteString(" END)")
	return b.String(), all
}

// postureSurfaceTypes are counted as surface whether or not they are marked
// internet accessible; any other asset type counts when it is.
var postureSurfaceTypes = EASMSurfaceTypes

// postureFactsQuery reads one row per surface asset (attributed, live, not
// archived) with raw points per category, plus the row of issues without
// an asset. $1 tenant, $2 surface types, $3 counted exposure types.
func postureFactsQuery() string {
	catCase, _ := exposureCategorySQL()
	hij := posture.IndexOf(posture.CatHijackable)
	pivot := func(kind string) string {
		parts := make([]string, 0, posture.NumCategories-1)
		for i := 1; i < posture.NumCategories; i++ {
			parts = append(parts, fmt.Sprintf("COALESCE(SUM(%s) FILTER (WHERE cat = %d), 0)", kind, i))
		}
		return strings.Join(parts, ", ")
	}
	return `
	WITH surface AS (
		SELECT a.id, a.name, a.criticality, a.is_crown_jewel FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND NOT a.program_only
		  AND a.status IN ('active', 'stale')
		  AND (a.asset_type = ANY($2) OR a.is_internet_accessible)
		  AND NOT EXISTS (SELECT 1 FROM asset_attributions iv WHERE iv.tenant_id = $1 AND iv.asset_id = a.id
		                  AND iv.state IN ('discovered', 'needs_review', 'candidate', 'rejected'))
	),
	vul AS (
		SELECT s.asset_id,
		       SUM(s.finding_count * ` + severityPointsSQL("s.severity") + ` * CASE WHEN s.kev THEN ` + fmt.Sprintf("%g", posture.KEVMultiplier) + ` ELSE 1 END) AS pts,
		       SUM(s.finding_count) FILTER (WHERE ` + severityPointsSQL("s.severity") + ` > 0) AS n
		FROM dash_asset_state s
		WHERE s.tenant_id = $1 AND s.lens = 'open' AND s.source <> 'pentest'
		GROUP BY s.asset_id
	),
	ev AS (
		SELECT COALESCE(e.asset_id, '00000000-0000-0000-0000-000000000000'::uuid) AS asset_id,
		       ` + catCase + ` AS cat, ` + severityPointsSQL("e.severity") + ` AS pts
		FROM exposure_events e
		WHERE e.tenant_id = $1 AND e.state = 'active' AND e.event_type = ANY($3)
		  AND e.source NOT IN (` + postureBridgedSources + `)
	),
	evc AS (
		SELECT asset_id, cat,
		       CASE WHEN cat = ` + fmt.Sprint(hij) + ` THEN MAX(pts) ELSE SUM(pts) END AS pts,
		       CASE WHEN cat = ` + fmt.Sprint(hij) + ` THEN (CASE WHEN MAX(pts) > 0 THEN 1 ELSE 0 END)
		            ELSE COUNT(*) FILTER (WHERE pts > 0) END AS n
		FROM ev GROUP BY asset_id, cat
	),
	evp AS (
		SELECT asset_id, ` + pivot("pts") + `, ` + pivot("n") + ` FROM evc GROUP BY asset_id
	)
	SELECT s.id, s.name, s.criticality, s.is_crown_jewel, COALESCE(v.pts, 0), COALESCE(v.n, 0), evp.*
	FROM surface s
	LEFT JOIN vul v ON v.asset_id = s.id
	LEFT JOIN evp ON evp.asset_id = s.id
	UNION ALL
	SELECT '00000000-0000-0000-0000-000000000000'::uuid, '', 'medium', false, 0, 0, evp.*
	FROM evp WHERE evp.asset_id = '00000000-0000-0000-0000-000000000000'::uuid`
}

// postureFact is one row to store.
type postureFact struct {
	assetID     string
	name        string
	root        string
	criticality string
	points      [posture.NumCategories]float64
	issues      [posture.NumCategories]int64
}

// Rebuild implements posture.Repository.
func (r *EASMPostureRepository) Rebuild(ctx context.Context, tenantID shared.ID) (posture.Sums, error) {
	var total posture.Sums
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return total, fmt.Errorf("begin posture rebuild: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLocalStatementTimeout(ctx, tx, postureRebuildTimeout); err != nil {
		return total, err
	}
	var locked bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('easm_posture:' || $1::text))`,
		tenantID.String()).Scan(&locked); err != nil {
		return total, fmt.Errorf("posture lock: %w", err)
	}
	if !locked {
		return total, posture.ErrBusy
	}
	_, exposureTypes := exposureCategorySQL()
	//nolint:gosec // G202: the query is built from constants only; values are bound
	rows, err := tx.QueryContext(ctx, postureFactsQuery(), tenantID.String(), pq.Array(postureSurfaceTypes), pq.Array(exposureTypes))
	if err != nil {
		return total, fmt.Errorf("posture facts: %w", err)
	}
	facts, err := scanPostureFacts(rows, &total)
	if err != nil {
		return total, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM easm_posture_assets WHERE tenant_id = $1`, tenantID.String()); err != nil {
		return total, fmt.Errorf("clear posture facts: %w", err)
	}
	for start := 0; start < len(facts); start += postureInsertChunk {
		if err := insertPostureFacts(ctx, tx, tenantID, facts[start:min(start+postureInsertChunk, len(facts))]); err != nil {
			return total, err
		}
	}
	if err := tx.Commit(); err != nil {
		return total, fmt.Errorf("commit posture rebuild: %w", err)
	}
	return total, nil
}

// scanPostureFacts reads the facts query, applies the criticality
// multiplier and the root domain, and adds every row to total.
func scanPostureFacts(rows *sql.Rows, total *posture.Sums) ([]postureFact, error) {
	defer rows.Close()
	var out []postureFact
	for rows.Next() {
		var (
			f       postureFact
			crown   bool
			evAsset sql.NullString
			ev      [2 * (posture.NumCategories - 1)]sql.NullFloat64
		)
		dest := []any{&f.assetID, &f.name, &f.criticality, &crown, &f.points[0], &f.issues[0], &evAsset}
		for i := range ev {
			dest = append(dest, &ev[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan posture fact: %w", err)
		}
		for i := 1; i < posture.NumCategories; i++ {
			f.points[i] = ev[i-1].Float64
			f.issues[i] = int64(ev[posture.NumCategories-1+i-1].Float64)
		}
		m := posture.Multiplier(f.criticality, crown)
		f.criticality = posture.EffectiveCriticality(f.criticality, crown)
		for i := range f.points {
			f.points[i] *= m
		}
		noAsset := f.assetID == posture.NoAsset.String()
		if !noAsset {
			f.root = truncateRunes(posture.RootDomain(f.name), 255)
			total.Assets++
		}
		f.name = truncateRunes(f.name, 255)
		for i := range f.points {
			total.Points[i] += f.points[i]
			total.Issues[i] += f.issues[i]
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func insertPostureFacts(ctx context.Context, tx *sql.Tx, tenantID shared.ID, facts []postureFact) error {
	ids := make([]string, len(facts))
	names := make([]string, len(facts))
	roots := make([]string, len(facts))
	crits := make([]string, len(facts))
	var pts [posture.NumCategories][]float64
	var iss [posture.NumCategories][]int64
	for i, f := range facts {
		ids[i], names[i], roots[i], crits[i] = f.assetID, f.name, f.root, f.criticality
		for c := range pts {
			pts[c] = append(pts[c], f.points[c])
			iss[c] = append(iss[c], f.issues[c])
		}
	}
	args := []any{tenantID.String(), pq.Array(ids), pq.Array(names), pq.Array(roots), pq.Array(crits)}
	cols := []string{"asset_id", "asset_name", "root_domain", "criticality"}
	unnest := []string{"$2::uuid[]", "$3::text[]", "$4::text[]", "$5::text[]"}
	for c := range pts {
		args = append(args, pq.Array(pts[c]))
		cols = append(cols, posturePointCols[c])
		unnest = append(unnest, fmt.Sprintf("$%d::numeric[]", len(args)))
	}
	for c := range iss {
		args = append(args, pq.Array(iss[c]))
		cols = append(cols, postureIssueCols[c])
		unnest = append(unnest, fmt.Sprintf("$%d::int[]", len(args)))
	}
	//nolint:gosec // G202: column names and placeholders are constants
	q := `INSERT INTO easm_posture_assets (tenant_id, ` + strings.Join(cols, ", ") + `)
		SELECT $1, u.* FROM unnest(` + strings.Join(unnest, ", ") + `) AS u`
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("insert posture facts: %w", err)
	}
	return nil
}

func checkPostureWhere(w *filterspec.Where) error {
	if w == nil || !strings.HasPrefix(w.SQL, posture.Fields.TenantSQL+" = $") {
		return errors.New("posture filter was not compiled for a tenant")
	}
	return nil
}

// GroupsWhere implements posture.Repository.
func (r *EASMPostureRepository) GroupsWhere(ctx context.Context, w *filterspec.Where) ([]posture.GroupRow, error) {
	if err := checkPostureWhere(w); err != nil {
		return nil, err
	}
	sums := make([]string, 0, 2*posture.NumCategories)
	for _, c := range posturePointCols {
		sums = append(sums, "COALESCE(SUM(p."+c+"), 0)")
	}
	for _, c := range postureIssueCols {
		sums = append(sums, "COALESCE(SUM(p."+c+"), 0)")
	}
	//nolint:gosec // G202: registry SQL and constants; values bound
	q := `SELECT p.root_domain, p.criticality,
		COUNT(*) FILTER (WHERE p.asset_id <> '00000000-0000-0000-0000-000000000000'::uuid), ` + strings.Join(sums, ", ") + `
		FROM easm_posture_assets p WHERE ` + w.SQL + ` AND ` + posture.LiveSQL + `
		GROUP BY p.root_domain, p.criticality ORDER BY p.root_domain, p.criticality`
	qctx, cancel := context.WithTimeout(ctx, postureReadTimeout)
	defer cancel()
	rows, err := r.db.QueryContext(qctx, q, w.Args...)
	if err != nil {
		return nil, fmt.Errorf("posture groups: %w", err)
	}
	defer rows.Close()
	var out []posture.GroupRow
	for rows.Next() {
		var g posture.GroupRow
		dest := []any{&g.RootDomain, &g.Criticality, &g.Sums.Assets}
		for i := range g.Sums.Points {
			dest = append(dest, &g.Sums.Points[i])
		}
		for i := range g.Sums.Issues {
			dest = append(dest, &g.Sums.Issues[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan posture group: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ItemsWhere implements posture.Repository.
func (r *EASMPostureRepository) ItemsWhere(ctx context.Context, w *filterspec.Where, limit int) ([]posture.Item, error) {
	if err := checkPostureWhere(w); err != nil {
		return nil, err
	}
	values := make([]string, 0, posture.NumCategories)
	urgency := make([]string, 0, posture.NumCategories)
	for i, c := range posture.Categories() {
		values = append(values, fmt.Sprintf("('%s', p.%s, p.%s)", c, posturePointCols[i], postureIssueCols[i]))
		urgency = append(urgency, fmt.Sprintf("WHEN '%s' THEN %g", c, posture.Urgency(c, 1)))
	}
	limitPH := fmt.Sprintf("$%d", w.NextArg)
	args := append(append([]any(nil), w.Args...), max(limit, 1))
	//nolint:gosec // G202: registry SQL and constants; values bound
	q := `SELECT p.asset_id, p.asset_name, x.cat, x.pts, x.n
		FROM easm_posture_assets p
		CROSS JOIN LATERAL (VALUES ` + strings.Join(values, ", ") + `) AS x(cat, pts, n)
		WHERE ` + w.SQL + ` AND ` + posture.LiveSQL + ` AND x.pts > 0
		ORDER BY x.pts * (CASE x.cat ` + strings.Join(urgency, " ") + ` ELSE 0 END) DESC, p.asset_id, x.cat
		LIMIT ` + limitPH
	qctx, cancel := context.WithTimeout(ctx, postureReadTimeout)
	defer cancel()
	rows, err := r.db.QueryContext(qctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("posture items: %w", err)
	}
	defer rows.Close()
	var out []posture.Item
	for rows.Next() {
		var it posture.Item
		var cat string
		if err := rows.Scan(&it.AssetID, &it.Name, &cat, &it.Points, &it.Issues); err != nil {
			return nil, fmt.Errorf("scan posture item: %w", err)
		}
		it.Category = posture.Category(cat)
		out = append(out, it)
	}
	return out, rows.Err()
}

const postureStateColumns = `tenant_id, refresh_every, next_refresh_at, computed_at, duration_ms, assets, score, grade,
	previous_score, previous_grade, last_error, failed_at, last_requested_at`

func scanPostureState(row interface{ Scan(...any) error }) (*posture.State, error) {
	var (
		s                    posture.State
		every                string
		score, prev          sql.NullInt64
		grade, prevGrade     sql.NullString
		next, computed, fail sql.NullTime
		requested            sql.NullTime
	)
	if err := row.Scan(&s.TenantID, &every, &next, &computed, &s.DurationMS, &s.Assets, &score, &grade,
		&prev, &prevGrade, &s.LastError, &fail, &requested); err != nil {
		return nil, err
	}
	s.RefreshEvery = posture.Schedule(every)
	s.NextRefreshAt, s.ComputedAt, s.FailedAt, s.LastRequestedAt = nullTimeValue(next), nullTimeValue(computed), nullTimeValue(fail), nullTimeValue(requested)
	if score.Valid {
		v := int(score.Int64)
		s.Score = &v
	}
	if prev.Valid {
		v := int(prev.Int64)
		s.PreviousScore = &v
	}
	s.Grade, s.PreviousGrade = grade.String, prevGrade.String
	return &s, nil
}

// EnsureState implements posture.Repository.
func (r *EASMPostureRepository) EnsureState(ctx context.Context, tenantID shared.ID) (*posture.State, error) {
	if _, err := r.db.ExecContext(ctx, `INSERT INTO easm_posture_state (tenant_id, refresh_every, next_refresh_at)
		VALUES ($1, $2, now()) ON CONFLICT (tenant_id) DO NOTHING`, tenantID.String(), string(posture.DefaultSchedule)); err != nil {
		return nil, fmt.Errorf("create posture state: %w", err)
	}
	s, err := scanPostureState(r.db.QueryRowContext(ctx,
		`SELECT `+postureStateColumns+` FROM easm_posture_state WHERE tenant_id = $1`, tenantID.String()))
	if err != nil {
		return nil, fmt.Errorf("read posture state: %w", err)
	}
	return s, nil
}

// SetSchedule implements posture.Repository.
func (r *EASMPostureRepository) SetSchedule(ctx context.Context, tenantID shared.ID, s posture.Schedule, next *time.Time) (*posture.State, error) {
	if _, err := r.EnsureState(ctx, tenantID); err != nil {
		return nil, err
	}
	st, err := scanPostureState(r.db.QueryRowContext(ctx, `UPDATE easm_posture_state
		SET refresh_every = $2, next_refresh_at = $3, updated_at = now()
		WHERE tenant_id = $1 RETURNING `+postureStateColumns, tenantID.String(), string(s), next))
	if err != nil {
		return nil, fmt.Errorf("set posture schedule: %w", err)
	}
	return st, nil
}

// TakeRecalculateBudget implements posture.Repository: one statement, so two
// concurrent requests cannot both pass.
func (r *EASMPostureRepository) TakeRecalculateBudget(ctx context.Context, tenantID shared.ID, now time.Time, every time.Duration) (bool, time.Duration, error) {
	if _, err := r.EnsureState(ctx, tenantID); err != nil {
		return false, 0, err
	}
	cutoff := now.Add(-every)
	var took bool
	var last sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		WITH prev AS (SELECT last_requested_at FROM easm_posture_state WHERE tenant_id = $1 FOR UPDATE),
		upd AS (
			UPDATE easm_posture_state SET last_requested_at = $2, updated_at = now()
			WHERE tenant_id = $1 AND (last_requested_at IS NULL OR last_requested_at <= $3)
			RETURNING 1
		)
		SELECT EXISTS (SELECT 1 FROM upd), (SELECT last_requested_at FROM prev)`,
		tenantID.String(), now, cutoff).Scan(&took, &last)
	if err != nil {
		return false, 0, fmt.Errorf("posture recalculate budget: %w", err)
	}
	if took {
		return true, 0, nil
	}
	wait := every
	if last.Valid {
		wait = last.Time.Add(every).Sub(now)
	}
	return false, max(wait, time.Second), nil
}

// ClaimDueForPlatform implements posture.Repository.
func (r *EASMPostureRepository) ClaimDueForPlatform(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH due AS (
			SELECT tenant_id FROM easm_posture_state
			WHERE next_refresh_at IS NOT NULL AND next_refresh_at <= $1
			ORDER BY next_refresh_at LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		UPDATE easm_posture_state s SET next_refresh_at = $1 + $3::interval
		FROM due WHERE s.tenant_id = due.tenant_id
		RETURNING s.tenant_id`,
		now, max(limit, 1), fmt.Sprintf("%d seconds", int(lease.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("claim due posture: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan due posture: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SaveResult implements posture.Repository.
func (r *EASMPostureRepository) SaveResult(ctx context.Context, tenantID shared.ID, res posture.Result, next *time.Time) error {
	var grade any
	if res.Grade != "" {
		grade = res.Grade
	}
	_, err := r.db.ExecContext(ctx, `UPDATE easm_posture_state SET
		previous_score = CASE WHEN score IS DISTINCT FROM $5::smallint THEN score ELSE previous_score END,
		previous_grade = CASE WHEN score IS DISTINCT FROM $5::smallint THEN grade ELSE previous_grade END,
		computed_at = $2, duration_ms = $3, assets = $4, score = $5::smallint, grade = $6::text,
		next_refresh_at = $7, last_error = '', failed_at = NULL, updated_at = now()
		WHERE tenant_id = $1`,
		tenantID.String(), res.ComputedAt, res.DurationMS, res.Assets, res.Score, grade, next)
	if err != nil {
		return fmt.Errorf("save posture result: %w", err)
	}
	return nil
}

// MarkFailed implements posture.Repository.
func (r *EASMPostureRepository) MarkFailed(ctx context.Context, tenantID shared.ID, code string, next *time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE easm_posture_state SET last_error = left($2, 200), failed_at = now(),
		next_refresh_at = $3, updated_at = now() WHERE tenant_id = $1`, tenantID.String(), code, next)
	if err != nil {
		return fmt.Errorf("mark posture failed: %w", err)
	}
	return nil
}

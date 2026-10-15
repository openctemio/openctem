package postgres

// Cross-rule finding correlation storage (research/134 section 12;
// pkg/domain/correlation decides). An auto link makes the member a
// duplicate of the primary (duplicate_of, resolution "correlated") and
// keeps the member's status and the primary's severity from before, so a
// release restores them exactly. Nothing is deleted.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/correlation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ResolutionCorrelated marks a duplicate made by correlation.
const ResolutionCorrelated = "correlated"

// correlationOpenStatuses are the statuses a finding may be correlated
// from: open work (never a triaged or closed finding).
var correlationOpenStatuses = []string{"new", "confirmed", "in_progress", "fix_applied"}

// FindingCorrelationRepository stores injection points and correlations.
type FindingCorrelationRepository struct {
	db *DB
}

// NewFindingCorrelationRepository creates the repository.
func NewFindingCorrelationRepository(db *DB) *FindingCorrelationRepository {
	return &FindingCorrelationRepository{db: db}
}

var _ ingest.CorrelationStore = (*FindingCorrelationRepository)(nil)

// UpsertInjectionPoints records each finding's injection point.
func (r *FindingCorrelationRepository) UpsertInjectionPoints(ctx context.Context, tenantID shared.ID, rows []ingest.InjectionPointRow) error {
	for _, row := range rows {
		p := row.Point
		if !p.Valid() || len(p.Key()) > 4096 || len(p.Origin) > 512 || len(p.Path) > 2048 || len(p.Params) > 64 {
			continue
		}
		matched := row.MatchedURL
		if len(matched) > 4096 {
			matched = matched[:4096]
		}
		if _, err := r.db.ExecContext(ctx, `
			INSERT INTO finding_injection_points (finding_id, tenant_id, asset_id, kind, point_key, origin, path, method, params, stripped, matched_url, updated_at)
			SELECT f.id, f.tenant_id, f.asset_id, 'dast', $3, $4, $5, $6, COALESCE($7::text[], '{}'), NULLIF($8, ''), NULLIF($9, ''), NOW()
			FROM findings f WHERE f.tenant_id = $1 AND f.fingerprint = $2 AND f.asset_id IS NOT NULL
			ON CONFLICT (finding_id) DO UPDATE SET point_key = EXCLUDED.point_key, origin = EXCLUDED.origin, path = EXCLUDED.path,
				method = EXCLUDED.method, params = EXCLUDED.params, stripped = EXCLUDED.stripped,
				matched_url = EXCLUDED.matched_url, updated_at = NOW()`,
			tenantID.String(), row.Fingerprint, p.Key(), p.Origin, p.Path, p.Method, pq.Array(p.Params), p.Stripped, matched); err != nil {
			return fmt.Errorf("upsert injection point: %w", err)
		}
	}
	return nil
}

// Options reads the tenant's switches: both tiers on unless turned off.
func (r *FindingCorrelationRepository) Options(ctx context.Context, tenantID shared.ID) (correlation.Options, error) {
	var autoOff, suggestOff bool
	err := r.db.QueryRowContext(ctx, `SELECT
			COALESCE((settings->'finding_correlation'->>'auto_disabled')::boolean, FALSE),
			COALESCE((settings->'finding_correlation'->>'suggestions_disabled')::boolean, FALSE)
		FROM tenants WHERE id = $1`, tenantID.String()).Scan(&autoOff, &suggestOff)
	if err != nil {
		return correlation.Options{}, err
	}
	return correlation.Options{Auto: !autoOff, Suggestions: !suggestOff}, nil
}

type corrCandidate struct {
	c           correlation.Candidate
	fingerprint string
	status      string
	severity    string
	activePrim  string
	pointKey    string
}

// Correlate re-derives the correlations of the assets.
func (r *FindingCorrelationRepository) Correlate(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, sighted []string, opt correlation.Options) ([]shared.ID, error) {
	var released []shared.ID
	seen := map[string]bool{}
	for _, fp := range sighted {
		seen[fp] = true
	}
	for _, a := range assetIDs {
		rel, err := r.correlateAsset(ctx, tenantID, a, seen, opt)
		if err != nil {
			return released, err
		}
		released = append(released, rel...)
	}
	return released, nil
}

// CorrelationReport counts what one asset's re-derivation did or would do.
type CorrelationReport struct {
	Linked, Released, Suggested int
}

func (r *FindingCorrelationRepository) correlateAsset(ctx context.Context, tenantID, assetID shared.ID, seen map[string]bool, opt correlation.Options) ([]shared.ID, error) {
	plan, cands, err := r.planAsset(ctx, tenantID, assetID, seen, opt, nil)
	if err != nil {
		return nil, err
	}
	return r.applyPlan(ctx, tenantID, plan, cands)
}

// planAsset loads one asset's candidates and links and decides.
// override supplies injection points not stored yet (a dry-run backfill).
func (r *FindingCorrelationRepository) planAsset(ctx context.Context, tenantID, assetID shared.ID, seen map[string]bool, opt correlation.Options,
	override map[string]correlation.InjectionPoint) (correlation.Plan, map[string]*corrCandidate, error) {
	tenant := tenantID.String()
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.fingerprint, f.status, f.severity, COALESCE(f.cve_id, ''), COALESCE(f.cwe_ids, '{}'), f.created_at,
		       COALESCE(ip.point_key, ''), COALESCE(ip.origin, ''), COALESCE(ip.path, ''), COALESCE(ip.method, ''), COALESCE(ip.params, '{}'),
		       COALESCE(c.primary_id::text, ''), COALESCE(c.member_prior_status, '')
		FROM findings f
		LEFT JOIN finding_injection_points ip ON ip.finding_id = f.id
		LEFT JOIN finding_correlations c ON c.tenant_id = f.tenant_id AND c.member_id = f.id AND c.state = 'active' AND c.tier = 'auto'
		WHERE f.tenant_id = $1 AND f.asset_id = $2
		  AND (f.status = ANY($3) OR (f.status = 'duplicate' AND c.id IS NOT NULL))
		LIMIT 5000`, tenant, assetID.String(), pq.Array(correlationOpenStatuses))
	if err != nil {
		return correlation.Plan{}, nil, fmt.Errorf("load correlation candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	cands := map[string]*corrCandidate{}
	var list []correlation.Candidate
	for rows.Next() {
		var (
			x       corrCandidate
			id, cve string
			cwes    []string
			created time.Time
			prior   string
			params  []string
		)
		if err := rows.Scan(&id, &x.fingerprint, &x.status, &x.severity, &cve, pq.Array(&cwes), &created,
			&x.pointKey, &x.c.Point.Origin, &x.c.Point.Path, &x.c.Point.Method, pq.Array(&params),
			&x.activePrim, &prior); err != nil {
			return correlation.Plan{}, nil, err
		}
		for i := range cwes {
			cwes[i] = correlation.NormalizeCWE(cwes[i])
		}
		x.c.ID, x.c.AssetID, x.c.CVE, x.c.CWEs, x.c.CreatedAt = id, assetID.String(), strings.ToUpper(strings.TrimSpace(cve)), cwes, created
		x.c.Point.Params = params
		if x.pointKey == "" {
			pt, ok := override[id]
			if !ok {
				continue // not a web finding with a known injection point
			}
			x.c.Point, x.pointKey = pt, pt.Key()
		}
		x.c.Severity = severityRank(x.severity)
		x.c.Sighted = seen[x.fingerprint]
		x.c.Open = x.status != "duplicate" || isOpenStatus(prior)
		cands[id] = &x
		list = append(list, x.c)
	}
	if err := rows.Err(); err != nil {
		return correlation.Plan{}, nil, err
	}
	links, err := r.existingLinks(ctx, tenant, cands)
	if err != nil {
		return correlation.Plan{}, nil, err
	}
	return correlation.Decide(list, links, opt), cands, nil
}

func (r *FindingCorrelationRepository) existingLinks(ctx context.Context, tenant string, cands map[string]*corrCandidate) ([]correlation.Link, error) {
	if len(cands) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(cands))
	for id := range cands {
		ids = append(ids, id)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT primary_id, member_id, tier, state FROM finding_correlations
		WHERE tenant_id = $1 AND state IN ('active', 'rejected') AND (member_id = ANY($2) OR primary_id = ANY($2))`, tenant, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []correlation.Link
	for rows.Next() {
		var l correlation.Link
		var state string
		if err := rows.Scan(&l.PrimaryID, &l.MemberID, &l.Tier, &state); err != nil {
			return nil, err
		}
		l.Rejected = state == "rejected"
		out = append(out, l)
	}
	return out, rows.Err()
}

// applyPlan carries out releases, then links, then suggestions, each in its
// own transaction with the rows re-checked under lock.
func (r *FindingCorrelationRepository) applyPlan(ctx context.Context, tenantID shared.ID, plan correlation.Plan, cands map[string]*corrCandidate) ([]shared.ID, error) {
	tenant := tenantID.String()
	var released []shared.ID
	for _, l := range plan.Release {
		ok, err := r.release(ctx, tenant, l.MemberID, plan.Releases[l.MemberID], "released", nil)
		if err != nil {
			return released, err
		}
		if ok {
			if id, err := shared.IDFromString(l.MemberID); err == nil {
				released = append(released, id)
			}
		}
	}
	for _, l := range plan.Link {
		if err := r.link(ctx, tenant, l, plan.Reasons[l.MemberID], cands[l.MemberID].pointKey); err != nil {
			return released, err
		}
	}
	if err := r.refreshSuggestions(ctx, tenant, plan, cands); err != nil {
		return released, err
	}
	return released, nil
}

// link makes member a duplicate of primary when both are still open.
func (r *FindingCorrelationRepository) link(ctx context.Context, tenant string, l correlation.Link, reason, pointKey string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setFindingTransition(ctx, tx, findingTransition{
		Source: "correlation", Reason: "correlated", ActorName: "system: finding correlation",
		Message: "Linked as another detection of the same issue",
		Changes: map[string]any{"duplicate_of": l.PrimaryID, "correlation_reason": reason},
	}); err != nil {
		return err
	}
	var mStatus, mSev, pStatus, pSev string
	var mRes sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT status, severity, resolution FROM findings WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenant, l.MemberID).Scan(&mStatus, &mSev, &mRes); err != nil {
		return ignoreNoRows(err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT status, severity FROM findings WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenant, l.PrimaryID).Scan(&pStatus, &pSev); err != nil {
		return ignoreNoRows(err)
	}
	if !isOpenStatus(mStatus) || !isOpenStatus(pStatus) {
		return nil // triage happened meanwhile: never correlate a decided finding
	}
	// The primary's severity before its first member, kept for a release.
	prior := pSev
	_ = tx.QueryRowContext(ctx, `SELECT primary_prior_severity FROM finding_correlations
		WHERE tenant_id = $1 AND primary_id = $2 AND state = 'active' AND tier = 'auto' AND primary_prior_severity IS NOT NULL
		ORDER BY created_at LIMIT 1`, tenant, l.PrimaryID).Scan(&prior)
	if _, err := tx.ExecContext(ctx, `DELETE FROM finding_correlations WHERE tenant_id = $1 AND member_id = $2 AND state = 'active' AND tier = 'suggested'`,
		tenant, l.MemberID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_correlations (tenant_id, primary_id, member_id, kind, tier, state, reason, point_key,
			member_prior_status, member_prior_resolution, primary_prior_severity)
		VALUES ($1, $2, $3, 'dast', 'auto', 'active', $4, $5, $6, $7, $8)`,
		tenant, l.PrimaryID, l.MemberID, reason, pointKey, mStatus, mRes, prior); err != nil {
		return fmt.Errorf("insert correlation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = 'duplicate', duplicate_of = $3, resolution = $4, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`, tenant, l.MemberID, l.PrimaryID, ResolutionCorrelated); err != nil {
		return err
	}
	// The group counts once, at its worst severity.
	if severityRank(mSev) > severityRank(pSev) {
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET severity = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
			tenant, l.PrimaryID, mSev); err != nil {
			return err
		}
	}
	if err := auditCorrelation(ctx, tx, tenant, l.MemberID, "finding.duplicate_marked",
		"Finding correlated with "+l.PrimaryID+" ("+reason+")", map[string]string{"primary_id": l.PrimaryID, "member_id": l.MemberID, "reason": reason}); err != nil {
		return err
	}
	return tx.Commit()
}

// ConfirmSuggestion turns a "possibly related" suggestion into a
// correlation at a person's request: member becomes primary's correlated
// duplicate (reversible). False when no such suggestion is open or either
// finding left the open statuses.
func (r *FindingCorrelationRepository) ConfirmSuggestion(ctx context.Context, tenantID, primaryID, memberID shared.ID) (bool, error) {
	var pointKey string
	err := r.db.QueryRowContext(ctx, `SELECT point_key FROM finding_correlations WHERE tenant_id = $1 AND tier = 'suggested' AND state = 'active'
		AND ((primary_id = $2 AND member_id = $3) OR (primary_id = $3 AND member_id = $2)) LIMIT 1`,
		tenantID.String(), primaryID.String(), memberID.String()).Scan(&pointKey)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := r.link(ctx, tenantID.String(), correlation.Link{PrimaryID: primaryID.String(), MemberID: memberID.String(), Tier: correlation.TierAuto}, "confirmed", pointKey); err != nil {
		return false, err
	}
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM finding_correlations WHERE tenant_id = $1 AND primary_id = $2 AND member_id = $3
		AND tier = 'auto' AND state = 'active'`, tenantID.String(), primaryID.String(), memberID.String()).Scan(&n); err != nil {
		return false, err
	}
	return n == 1, nil
}

// ReleaseByUser undoes an auto correlation of member at a person's request
// and remembers it, so it is never linked automatically again. It returns
// false when member is not a correlated duplicate.
func (r *FindingCorrelationRepository) ReleaseByUser(ctx context.Context, tenantID, memberID, userID shared.ID) (bool, error) {
	var by *string
	if !userID.IsZero() {
		uid := userID.String()
		by = &uid
	}
	return r.release(ctx, tenantID.String(), memberID.String(), "released_by_user", "rejected", by)
}

// release restores member's status from before its correlation.
func (r *FindingCorrelationRepository) release(ctx context.Context, tenant, member, why, state string, by *string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	t := findingTransition{Source: "correlation", Reason: why, ActorName: "system: finding correlation",
		Message: "Released from its correlation: a detection of its own again"}
	if by != nil {
		t.ActorType, t.ActorID, t.ActorName = "user", *by, ""
	}
	if err := setFindingTransition(ctx, tx, t); err != nil {
		return false, err
	}
	var id, primary string
	var prior, priorRes, priorSev sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id, primary_id, member_prior_status, member_prior_resolution, primary_prior_severity
		FROM finding_correlations WHERE tenant_id = $1 AND member_id = $2 AND state = 'active' AND tier = 'auto' FOR UPDATE`,
		tenant, member).Scan(&id, &primary, &prior, &priorRes, &priorSev)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	status := prior.String
	if !isOpenStatus(status) {
		status = "new"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE finding_correlations SET state = $3, released_at = NOW(), released_reason = $4,
			released_by = $5, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`, tenant, id, state, why, by); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = $3, duplicate_of = NULL, resolution = $4, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status = 'duplicate'`, tenant, member, status, priorRes); err != nil {
		return false, err
	}
	// The primary's severity: its own from before, or a remaining member's
	// if worse.
	if priorSev.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE findings p SET severity = (
				SELECT s FROM (SELECT $3::varchar AS s UNION ALL
					SELECT m.severity FROM finding_correlations c JOIN findings m ON m.id = c.member_id AND m.tenant_id = c.tenant_id
					WHERE c.tenant_id = $1 AND c.primary_id = $2 AND c.state = 'active' AND c.tier = 'auto') x
				ORDER BY CASE lower(s) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC
				LIMIT 1), updated_at = NOW()
			WHERE p.tenant_id = $1 AND p.id = $2`, tenant, primary, priorSev.String); err != nil {
			return false, err
		}
	}
	if err := auditCorrelation(ctx, tx, tenant, member, "finding.updated", "Finding released from its correlation with "+primary+" ("+why+")",
		map[string]string{"primary_id": primary, "member_id": member, "reason": why}); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// refreshSuggestions replaces the asset's suggestions with the plan's.
func (r *FindingCorrelationRepository) refreshSuggestions(ctx context.Context, tenant string, plan correlation.Plan, cands map[string]*corrCandidate) error {
	ids := make([]string, 0, len(cands))
	for id := range cands {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil
	}
	if _, err := r.db.ExecContext(ctx, `DELETE FROM finding_correlations WHERE tenant_id = $1 AND tier = 'suggested' AND state = 'active'
		AND member_id = ANY($2)`, tenant, pq.Array(ids)); err != nil {
		return err
	}
	for _, l := range plan.Suggest {
		if _, err := r.db.ExecContext(ctx, `INSERT INTO finding_correlations (tenant_id, primary_id, member_id, kind, tier, state, reason, point_key)
			VALUES ($1, $2, $3, 'dast', 'suggested', 'active', $4, $5) ON CONFLICT DO NOTHING`,
			tenant, l.PrimaryID, l.MemberID, correlation.ReasonRelated, cands[l.MemberID].pointKey); err != nil {
			return err
		}
	}
	return nil
}

// Detection is one detection of an issue, for the primary's view.
type Detection struct {
	FindingID  string    `json:"finding_id"`
	RuleID     string    `json:"rule_id"`
	Title      string    `json:"title"`
	MatchedURL string    `json:"matched_url"`
	FirstSeen  time.Time `json:"first_seen"`
	Primary    bool      `json:"primary"`
}

// Detections lists the primary and its active auto-correlated members;
// related lists the "possibly related" suggestions naming it. Tenant scoped.
func (r *FindingCorrelationRepository) Detections(ctx context.Context, tenantID, findingID shared.ID) (detections, related []Detection, err error) {
	q := `SELECT f.id, COALESCE(f.rule_id, ''), COALESCE(f.title, ''), COALESCE(ip.matched_url, f.file_path, ''), f.first_detected_at, %s
		FROM findings f LEFT JOIN finding_injection_points ip ON ip.finding_id = f.id
		WHERE f.tenant_id = $1 AND %s ORDER BY f.first_detected_at, f.id LIMIT 100`
	scan := func(query string, args ...any) ([]Detection, error) {
		rows, err := r.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		var out []Detection
		for rows.Next() {
			var d Detection
			var first sql.NullTime
			if err := rows.Scan(&d.FindingID, &d.RuleID, &d.Title, &d.MatchedURL, &first, &d.Primary); err != nil {
				return nil, err
			}
			d.FirstSeen = first.Time
			out = append(out, d)
		}
		return out, rows.Err()
	}
	t, id := tenantID.String(), findingID.String()
	detections, err = scan(fmt.Sprintf(q, "f.id = $2", `(f.id = $2 OR f.id IN (SELECT member_id FROM finding_correlations
		WHERE tenant_id = $1 AND primary_id = $2 AND state = 'active' AND tier = 'auto'))`), t, id)
	if err != nil {
		return nil, nil, err
	}
	if len(detections) < 2 {
		detections = nil
	}
	related, err = scan(fmt.Sprintf(q, "FALSE", `f.id IN (SELECT CASE WHEN primary_id = $2 THEN member_id ELSE primary_id END
		FROM finding_correlations WHERE tenant_id = $1 AND state = 'active' AND tier = 'suggested' AND (primary_id = $2 OR member_id = $2))`), t, id)
	return detections, related, err
}

func auditCorrelation(ctx context.Context, tx *sql.Tx, tenant, findingID, action, msg string, meta map[string]string) error {
	b, _ := json.Marshal(meta)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
		VALUES (gen_random_uuid(), $1, $2, 'finding', $3, 'success', 'low', $4, $5::jsonb, NOW())`, tenant, action, findingID, msg, string(b)); err != nil {
		return fmt.Errorf("audit correlation: %w", err)
	}
	return nil
}

func isOpenStatus(s string) bool {
	for _, o := range correlationOpenStatuses {
		if s == o {
			return true
		}
	}
	return false
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

func ignoreNoRows(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

// CorrelationBackfill counts what a one-time correlation of existing findings
// did or would do.
type CorrelationBackfill struct {
	TenantID  string `json:"tenant_id"`
	Applied   bool   `json:"applied"`
	Points    int    `json:"injection_points"`
	Assets    int    `json:"assets"`
	Linked    int    `json:"would_link"`
	Suggested int    `json:"would_suggest"`
	Released  int    `json:"would_release"`
}

// Backfill derives the injection points of a tenant's DAST findings from
// their stored detection evidence and correlates every asset once. Without
// apply nothing is written. Idempotent.
func (r *FindingCorrelationRepository) Backfill(ctx context.Context, tenantID shared.ID, apply bool) (*CorrelationBackfill, error) {
	rep := &CorrelationBackfill{TenantID: tenantID.String(), Applied: apply}
	points, assets, err := r.storedPoints(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rep.Points, rep.Assets = len(points), len(assets)
	opt, err := r.Options(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if apply {
		if err := r.upsertPointsByID(ctx, tenantID, points); err != nil {
			return nil, err
		}
	}
	override := map[string]correlation.InjectionPoint{}
	for id, p := range points {
		override[id] = p.Point
	}
	for _, a := range assets {
		plan, cands, err := r.planAsset(ctx, tenantID, a, nil, opt, override)
		if err != nil {
			return nil, err
		}
		rep.Linked += len(plan.Link)
		rep.Suggested += len(plan.Suggest)
		rep.Released += len(plan.Release)
		if apply {
			if _, err := r.applyPlan(ctx, tenantID, plan, cands); err != nil {
				return nil, err
			}
		}
	}
	return rep, nil
}

// storedPoints computes the injection point of each DAST finding (by id)
// from its newest detection exchange: the request URL and method, and the
// Location headers of the response as the payloads it echoed. A finding
// without stored evidence gets its matched URL without payload stripping.
func (r *FindingCorrelationRepository) storedPoints(ctx context.Context, tenantID shared.ID) (map[string]ingest.InjectionPointRow, []shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.asset_id, COALESCE(f.file_path, ''),
		       COALESCE((SELECT x->>'v' FROM jsonb_array_elements(f.identity_key->'fields') x WHERE x->>'n' = 'method'), ''),
		       COALESCE((SELECT x->>'v' FROM jsonb_array_elements(f.identity_key->'fields') x WHERE x->>'n' = 'params'), ''),
		       COALESCE(e.content->'http'->'request'->>'url', ''),
		       COALESCE(e.content->'http'->'request'->>'method', ''),
		       COALESCE((SELECT array_agg(h->>'value') FROM jsonb_array_elements(e.content->'http'->'response'->'headers') h
		                 WHERE lower(h->>'name') = 'location'), '{}')
		FROM findings f
		LEFT JOIN LATERAL (SELECT content FROM finding_evidence ev WHERE ev.tenant_id = f.tenant_id AND ev.finding_id = f.id
		                   AND ev.origin = 'detection' AND ev.kind = 'http_exchange' ORDER BY ev.created_at DESC LIMIT 1) e ON TRUE
		WHERE f.tenant_id = $1 AND f.asset_id IS NOT NULL AND f.identity_key->>'kind' = 'dast' AND f.status <> 'duplicate'
		LIMIT 50000`, tenantID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("load dast findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]ingest.InjectionPointRow{}
	seenAsset := map[string]bool{}
	var assets []shared.ID
	for rows.Next() {
		var id, asset, filePath, keyMethod, keyParams, reqURL, reqMethod string
		var locations []string
		if err := rows.Scan(&id, &asset, &filePath, &keyMethod, &keyParams, &reqURL, &reqMethod, pq.Array(&locations)); err != nil {
			return nil, nil, err
		}
		matched := reqURL
		if matched == "" {
			matched = filePath
		}
		method := reqMethod
		if method == "" {
			method = keyMethod
		}
		var params []string
		for _, n := range strings.Split(keyParams, ",") {
			// Query names come from the URL itself; others keep an unknown
			// location, so they only ever match each other.
			if n = strings.TrimSpace(n); n != "" && !queryHas(matched, n) {
				params = append(params, "unknown:"+n)
			}
		}
		pt, ok := correlation.Point(correlation.PointInput{MatchedURL: matched, Method: method, Params: params, Payloads: locations})
		if !ok {
			continue
		}
		aid, err := shared.IDFromString(asset)
		if err != nil {
			continue
		}
		out[id] = ingest.InjectionPointRow{AssetID: aid, Point: pt, MatchedURL: matched}
		if !seenAsset[asset] {
			seenAsset[asset] = true
			assets = append(assets, aid)
		}
	}
	return out, assets, rows.Err()
}

func queryHas(rawURL, name string) bool {
	i := strings.Index(rawURL, "?")
	if i < 0 {
		return false
	}
	for _, kv := range strings.Split(rawURL[i+1:], "&") {
		if k, _, _ := strings.Cut(kv, "="); k == name {
			return true
		}
	}
	return false
}

// upsertPointsByID stores points keyed by finding id.
func (r *FindingCorrelationRepository) upsertPointsByID(ctx context.Context, tenantID shared.ID, points map[string]ingest.InjectionPointRow) error {
	for id, row := range points {
		p := row.Point
		if !p.Valid() || len(p.Key()) > 4096 || len(p.Origin) > 512 || len(p.Path) > 2048 || len(p.Params) > 64 {
			continue
		}
		matched := row.MatchedURL
		if len(matched) > 4096 {
			matched = matched[:4096]
		}
		if _, err := r.db.ExecContext(ctx, `
			INSERT INTO finding_injection_points (finding_id, tenant_id, asset_id, kind, point_key, origin, path, method, params, stripped, matched_url, updated_at)
			SELECT f.id, f.tenant_id, f.asset_id, 'dast', $3, $4, $5, $6, COALESCE($7::text[], '{}'), NULLIF($8, ''), NULLIF($9, ''), NOW()
			FROM findings f WHERE f.tenant_id = $1 AND f.id = $2 AND f.asset_id IS NOT NULL
			ON CONFLICT (finding_id) DO NOTHING`,
			tenantID.String(), id, p.Key(), p.Origin, p.Path, p.Method, pq.Array(p.Params), p.Stripped, matched); err != nil {
			return fmt.Errorf("store injection point: %w", err)
		}
	}
	return nil
}

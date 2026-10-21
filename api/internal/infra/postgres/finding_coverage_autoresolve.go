package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Coverage-scoped auto-resolve of non-repository findings: the queries behind
// ingest.Service.EvaluateCommandCoverage.

// secretFindingSQL is true for a leaked-secret finding (by type or source) of
// the table alias. A secret is never closed by a scan that stops seeing it:
// removing it from the branch does not revoke it, and history keeps it.
func secretFindingSQL(alias string) string {
	return "(" + alias + ".finding_type = 'secret' OR " + alias + ".source = 'secret')"
}

// markSecretsNotObserved marks open, present secret findings stale
// (observation_state; the status stays) with a timeline entry. branch is true
// for default-branch (repository) findings. Tenant-scoped; the UPDATE
// re-checks status, type and branch, so a finding someone triaged since the
// candidates were read is left alone.
func (r *FindingRepository) markSecretsNotObserved(ctx context.Context, tenantID shared.ID, ids []shared.ID, message, actor string, branch bool) ([]shared.ID, error) {
	if autoResolvePaused(ctx, r.db, tenantID.String()) {
		return nil, nil
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	where := "f.branch_id IS NULL"
	if branch {
		where = "f.branch_id IS NOT NULL"
	}
	// The status does not change, so the status trigger writes no timeline
	// entry: write it here, for the findings that just went stale only.
	out, err := r.db.queryIDsWithTransition(ctx, findingTransition{
		Source: "secret_not_observed", Reason: "secret_not_observed", ActorType: "scanner", ActorName: actor,
		Message: message,
	}, `
		WITH upd AS (
			UPDATE findings f
			SET observation_state = 'stale', updated_at = NOW()
			WHERE f.tenant_id = $1
				AND f.id = ANY($2::uuid[])
				AND `+where+`
				AND f.status IN `+staleFromSQL+`
				AND f.observation_state = 'present'
				AND f.source NOT IN `+coverageProtectedSources+`
				AND `+secretFindingSQL("f")+`
			RETURNING f.id, f.tenant_id
		), act AS (
			INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
			SELECT u.tenant_id, u.id, 'metadata_updated', 'scanner', $3,
			       jsonb_build_object('observation_state', 'stale', 'reason', 'secret_not_observed'),
			       'secret_not_observed', $4
			FROM upd u
		)
		SELECT id::text FROM upd`, tenantID.String(), pq.Array(idStrs), actor, message)
	if err != nil {
		return nil, fmt.Errorf("mark secret findings not observed: %w", err)
	}
	return out, nil
}

// coverageProtectedSources are never closed by a scan.
const coverageProtectedSources = `('pentest', 'manual', 'bug_bounty', 'red_team')`

// CommandCoverage loads a command's state, the scan profile of the scan that
// queued it, and every v2 report filed under it.
func (r *FindingRepository) CommandCoverage(ctx context.Context, tenantID, commandID shared.ID) (*ingestreport.CommandCoverage, error) {
	c := &ingestreport.CommandCoverage{}
	var result []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT c.type, COALESCE(c.status, ''), c.result, COALESCE(s.profile_id::text, '')
		FROM commands c
		LEFT JOIN scans s ON s.tenant_id = c.tenant_id AND s.id::text = c.payload->>'scan_id'
		WHERE c.tenant_id = $1 AND c.id = $2`, tenantID.String(), commandID.String(),
	).Scan(&c.CommandType, &c.CommandStatus, &result, &c.ProfileID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load command coverage: %w", err)
	}
	c.Result = result

	rows, err := r.db.QueryContext(ctx, `
		SELECT report_id::text, sensor_id, state, tool_name, header, segment_outcomes, touched_asset_ids
		FROM ingest_reports
		WHERE tenant_id = $1 AND command_id = $2
		ORDER BY received_at`, tenantID.String(), commandID.String())
	if err != nil {
		return nil, fmt.Errorf("load command reports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			rep              ingestreport.CoverageReport
			sensorID, state  string
			header, outcomes []byte
			touched          []string
		)
		if err := rows.Scan(&rep.ReportID, &sensorID, &state, &rep.ToolName, &header, &outcomes, pq.Array(&touched)); err != nil {
			return nil, fmt.Errorf("scan command report: %w", err)
		}
		if rep.SensorID, err = shared.IDFromString(sensorID); err != nil {
			return nil, fmt.Errorf("command report sensor id: %w", err)
		}
		rep.State = protov2.ReportState(state)
		rep.Header = header
		if len(outcomes) > 0 {
			if err := json.Unmarshal(outcomes, &rep.SegmentOutcomes); err != nil {
				return nil, fmt.Errorf("command report segment outcomes: %w", err)
			}
		}
		for _, a := range touched {
			id, err := shared.IDFromString(a)
			if err != nil {
				return nil, fmt.Errorf("command report touched asset: %w", err)
			}
			rep.TouchedAssetIDs = append(rep.TouchedAssetIDs, id)
		}
		c.Reports = append(c.Reports, rep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate command reports: %w", err)
	}
	return c, nil
}

// CoverageStaleFindings returns the open, non-repository findings of the
// query's tool on its assets that the run did not report and that were last
// seen by a v2 run of the same scan profile, plus how many open findings of
// that tool those assets have (for the blinding guard). A finding whose last
// sighting cannot be tied to a run (v1 ingest, an import) is never a
// candidate: proof of coverage needs like-for-like runs.
//
// A leaked secret is never a candidate (its absence does not revoke it);
// MarkCoverageSecretsNotObserved marks it instead.
func (r *FindingRepository) CoverageStaleFindings(ctx context.Context, tenantID shared.ID, q ingestreport.CoverageQuery) ([]shared.ID, int, error) {
	return r.coverageStale(ctx, tenantID, q, false)
}

// MarkCoverageSecretsNotObserved marks the open secret findings a covered scan
// of the query no longer reported as stale (observation_state; the status
// stays) with a timeline entry. It never resolves.
func (r *FindingRepository) MarkCoverageSecretsNotObserved(ctx context.Context, tenantID shared.ID, q ingestreport.CoverageQuery) ([]shared.ID, error) {
	ids, _, err := r.coverageStale(ctx, tenantID, q, true)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	return r.markSecretsNotObserved(ctx, tenantID, ids, "A covered scan no longer reported it; a secret stays exposed until it is rotated", "system: covered scan", false)
}

func (r *FindingRepository) coverageStale(ctx context.Context, tenantID shared.ID, q ingestreport.CoverageQuery, secrets bool) ([]shared.ID, int, error) {
	if len(q.AssetIDs) == 0 || q.ToolName == "" {
		return nil, 0, nil
	}
	assets := make([]string, len(q.AssetIDs))
	for i, a := range q.AssetIDs {
		assets[i] = a.String()
	}
	seen := q.SeenScanIDs
	if seen == nil {
		seen = []string{}
	}
	rows, err := r.db.QueryContext(ctx, `
		WITH open_findings AS (
			SELECT f.id, f.tenant_id, f.scan_id
			FROM findings f
			WHERE f.tenant_id = $1
				AND f.asset_id = ANY($2)
				AND f.tool_name = $3
				AND f.branch_id IS NULL
				AND f.status IN `+autoResolveFromSQL+`
				AND f.source NOT IN `+coverageProtectedSources+`
				AND `+secretFindingSQL("f")+` = $6
		)
		SELECT o.id::text, COUNT(*) OVER () AS open_total,
			(
				NOT (COALESCE(o.scan_id, '') = ANY($4))
				AND EXISTS (
					SELECT 1
					FROM ingest_reports ir
					LEFT JOIN commands pc ON pc.id = ir.command_id AND pc.tenant_id = ir.tenant_id
					LEFT JOIN scans ps ON ps.tenant_id = ir.tenant_id AND ps.id::text = pc.payload->>'scan_id'
					WHERE ir.tenant_id = o.tenant_id
						AND ir.report_id::text = o.scan_id
						-- The last sighting must be a report of this tool: a
						-- finding another tool reported last (same profile, other
						-- command) stays open (RFC-043 interim cross-tool guard).
						AND ir.tool_name = $3
						AND COALESCE(ps.profile_id::text, '') = $5
				)
			) AS stale
		FROM open_findings o`,
		tenantID.String(), pq.Array(assets), q.ToolName, pq.Array(seen), q.ProfileID, secrets)
	if err != nil {
		return nil, 0, fmt.Errorf("coverage stale findings: %w", err)
	}
	defer rows.Close()
	var (
		stale []shared.ID
		open  int
	)
	for rows.Next() {
		var (
			idStr   string
			isStale bool
		)
		if err := rows.Scan(&idStr, &open, &isStale); err != nil {
			return nil, 0, fmt.Errorf("scan coverage candidate: %w", err)
		}
		if !isStale {
			continue
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		stale = append(stale, id)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate coverage candidates: %w", err)
	}
	return stale, open, nil
}

// ResolveCoverageStale closes the given findings as verified by a scan. It
// re-checks status and branch in the UPDATE itself, so a finding someone
// triaged since the candidates were read is left alone.
func (r *FindingRepository) ResolveCoverageStale(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	// A re-fingerprint run is re-keying this tenant (RFC-043 D11): a finding
	// whose old key this scan did not produce must not be closed as fixed.
	if autoResolvePaused(ctx, r.db, tenantID.String()) {
		return nil, nil
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	resolved, err := r.db.queryIDsWithTransition(ctx, findingTransition{ActivityType: "auto_resolved", Source: "auto", Reason: "not_found_in_full_scan", ActorType: "scanner",
		ActorName: "system: covered scan", Message: "A full, successful scan that covered it no longer reported it"}, `
		UPDATE findings f
		SET status = 'resolved',
			resolution = 'auto_fixed',
			closure_reason = 'fixed', verification = 'covered_scan',
			resolved_at = NOW(),
			updated_at = NOW()
		WHERE f.tenant_id = $1
			AND f.id = ANY($2)
			AND f.branch_id IS NULL
			AND f.status IN `+autoResolveFromSQL+`
			AND f.source NOT IN `+coverageProtectedSources+`
			AND NOT `+secretFindingSQL("f")+`
		RETURNING f.id::text`, tenantID.String(), pq.Array(idStrs))
	if err != nil {
		return nil, fmt.Errorf("resolve coverage-stale findings: %w", err)
	}
	return resolved, nil
}

// ResolveSourceMitigated resolves the open findings a source said are
// mitigated (docs/rfcs/RFC-047-tenable-sc-sensor-connector.md §7.6), or with
// dryRun only returns the ones it would resolve. A finding qualifies only
// when it is the tenant's, on the stated asset, under the stated key, open,
// not from a human source, last seen by the same tool, and last seen no later
// than the mitigation. Returns the ids resolved (or that would be).
func (r *FindingRepository) ResolveSourceMitigated(ctx context.Context, tenantID shared.ID, tool string,
	items []vulnerability.SourceMitigation, dryRun bool) ([]shared.ID, error) {
	if len(items) == 0 || tool == "" {
		return nil, nil
	}
	fps := make([]string, len(items))
	assets := make([]string, len(items))
	ats := make([]time.Time, len(items))
	for i, it := range items {
		fps[i] = it.Fingerprint
		assets[i] = it.AssetID.String()
		ats[i] = it.MitigatedAt.UTC()
	}
	match := `
		WITH m AS (
			SELECT * FROM unnest($3::text[], $4::uuid[], $5::timestamptz[]) AS m(fingerprint, asset_id, mitigated_at)
		)
		SELECT f.id
		FROM findings f
		JOIN m ON m.fingerprint = f.fingerprint AND m.asset_id = f.asset_id
		WHERE f.tenant_id = $1
			AND f.status IN ` + autoResolveFromSQL + `
			AND f.source NOT IN ` + coverageProtectedSources + `
			AND COALESCE(f.last_seen_tool, f.tool_name) = $2
			AND COALESCE(f.last_seen_at, f.created_at) <= m.mitigated_at`
	query := `SELECT id::text FROM (` + match + `) x`
	if !dryRun {
		query = `
		UPDATE findings f
		SET status = 'resolved',
			resolution = 'auto_fixed',
			closure_reason = 'fixed', verification = 'source_reported',
			resolved_at = NOW(),
			updated_at = NOW()
		WHERE f.tenant_id = $1 AND f.id IN (` + match + `)
			AND f.status IN ` + autoResolveFromSQL + `
		RETURNING f.id::text`
	}
	out, err := r.db.queryIDsWithTransition(ctx, findingTransition{ActivityType: "auto_resolved", Source: "auto", Reason: "source_mitigated", ActorType: "integration",
		ActorName: "system: source reported mitigated", Message: "Its source reported it mitigated", Changes: map[string]any{"scanner": tool}}, query, tenantID.String(), tool, pq.Array(fps), pq.Array(assets), pq.Array(ats))
	if err != nil {
		return nil, fmt.Errorf("resolve source-mitigated findings: %w", err)
	}
	return out, nil
}

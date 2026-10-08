package postgres

// Template provenance of findings' last sightings (research/18 O6;
// migration 001015).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

var _ vulnerability.TemplateProvenanceStore = (*FindingRepository)(nil)

// RecordTemplateSightings stores each sighting's (sanitized) provenance on
// the tenant's finding with that fingerprint. Sightings without a template
// digest are skipped: they leave the finding's baseline as it was.
func (r *FindingRepository) RecordTemplateSightings(ctx context.Context, tenantID shared.ID, sightings []vulnerability.TemplateSighting) (int64, error) {
	fps := make([]string, 0, len(sightings))
	tds := make([]string, 0, len(sightings))
	tps := make([]string, 0, len(sightings))
	tvs := make([]string, 0, len(sightings))
	tsds := make([]string, 0, len(sightings))
	for _, s := range sightings {
		p := s.Provenance.Sanitize()
		if p.Empty() || s.Fingerprint == "" {
			continue
		}
		fps = append(fps, s.Fingerprint)
		tds = append(tds, p.TemplateDigest)
		tps = append(tps, p.TemplatePath)
		tvs = append(tvs, p.TemplatesVersion)
		tsds = append(tsds, p.TemplatesDigest)
	}
	if len(fps) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE findings f
		SET template_digest = v.td,
		    template_path = NULLIF(v.tp, ''),
		    templates_version = NULLIF(v.tv, ''),
		    templates_digest = NULLIF(v.tsd, ''),
		    template_seen_at = NOW()
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS v(fp, td, tp, tv, tsd)
		WHERE f.tenant_id = $1 AND f.fingerprint = v.fp`,
		tenantID.String(), pq.Array(fps), pq.Array(tds), pq.Array(tps), pq.Array(tvs), pq.Array(tsds))
	if err != nil {
		return 0, fmt.Errorf("record template sightings: %w", err)
	}
	return res.RowsAffected()
}

// TemplateBaseline returns the provenance of the finding's last sighting.
func (r *FindingRepository) TemplateBaseline(ctx context.Context, tenantID, findingID shared.ID) (vulnerability.TemplateProvenance, error) {
	var td, tp, tv, tsd sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT template_digest, template_path, templates_version, templates_digest
		FROM findings WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), findingID.String()).Scan(&td, &tp, &tv, &tsd)
	if errors.Is(err, sql.ErrNoRows) {
		return vulnerability.TemplateProvenance{}, shared.ErrNotFound
	}
	if err != nil {
		return vulnerability.TemplateProvenance{}, fmt.Errorf("read template baseline: %w", err)
	}
	return vulnerability.TemplateProvenance{TemplateDigest: td.String, TemplatePath: tp.String,
		TemplatesVersion: tv.String, TemplatesDigest: tsd.String}, nil
}

// TemplateDriftedFindings returns those of ids whose last sighting
// recorded a template release digest other than runDigest (or any digest,
// when the run reported none): a covered run with different template
// content cannot prove them fixed (research/18 O6).
func (r *FindingRepository) TemplateDriftedFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID, runDigest string) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id::text FROM findings
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])
		  AND templates_digest IS NOT NULL
		  AND templates_digest IS DISTINCT FROM NULLIF($3, '')`,
		tenantID.String(), pq.Array(idStrs), runDigest)
	if err != nil {
		return nil, fmt.Errorf("template-drifted findings: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// MarkCoverageNotObserved moves still-open findings of ids to not_observed:
// a covered run did not report them but ran different template content,
// so their absence proves nothing (research/18 O6). The same guards as
// ResolveCoverageStale apply.
func (r *FindingRepository) MarkCoverageNotObserved(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if autoResolvePaused(ctx, r.db, tenantID.String()) {
		return nil, nil
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		UPDATE findings f
		SET status = 'not_observed', updated_at = NOW()
		WHERE f.tenant_id = $1
			AND f.id = ANY($2::uuid[])
			AND f.branch_id IS NULL
			AND f.status IN `+staleFromSQL+`
			AND f.source NOT IN `+coverageProtectedSources+`
		RETURNING f.id::text`, tenantID.String(), pq.Array(idStrs))
	if err != nil {
		return nil, fmt.Errorf("mark coverage findings not observed: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

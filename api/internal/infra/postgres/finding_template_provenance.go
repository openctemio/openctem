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
// the tenant's finding with that fingerprint, only when it differs from what
// the finding already stores (template_seen_at then means "the provenance
// last changed"; a re-seen finding keeps one row version per ingest). Sightings without a template
// digest that are not the organization's own rules are skipped: they leave
// the finding's baseline as it was.
//
// The rule source and the organization's template are decided here, in the
// finding's tenant only: a digest of one of the tenant's scanner templates
// (or, without a digest, a rule the sensor marked as the organization's
// whose id one template defines) links that template and makes the source
// "tenant"; any other digest is the platform's. Another tenant's template
// is never matched, whatever its content.
var _ vulnerability.RuleProvenanceReader = (*FindingRepository)(nil)

func (r *FindingRepository) RecordTemplateSightings(ctx context.Context, tenantID shared.ID, sightings []vulnerability.TemplateSighting) (int64, error) {
	n := len(sightings)
	fps, tds, tps, tvs, tsds := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	rss, rids := make([]string, 0, n), make([]string, 0, n)
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
		rss = append(rss, p.RuleSource)
		rids = append(rids, p.RuleID)
	}
	if len(fps) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE findings f
		SET template_digest = NULLIF(v.td, ''),
		    template_path = NULLIF(v.tp, ''),
		    templates_version = NULLIF(v.tv, ''),
		    templates_digest = NULLIF(v.tsd, ''),
		    template_seen_at = NOW(),
		    rule_source = CASE WHEN v.rs = 'tenant' OR st.id IS NOT NULL THEN 'tenant'
		                       WHEN v.td <> '' THEN 'platform' END,
		    custom_template_id = st.id,
		    custom_template_version = st.version
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[])
		       AS v(fp, td, tp, tv, tsd, rs, rid)
		LEFT JOIN LATERAL (
			SELECT t.id, t.version
			FROM scanner_templates t
			WHERE t.tenant_id = $1
			  AND ((v.td <> '' AND t.content_hash = substr(v.td, 8))
			    OR (v.td = '' AND v.rs = 'tenant' AND v.rid <> ''
			        AND (t.metadata->>'id' = v.rid OR COALESCE(t.metadata->'rule_ids', '[]'::jsonb) ? v.rid)))
			ORDER BY t.updated_at DESC
			LIMIT 1
		) st ON TRUE
		WHERE f.tenant_id = $1 AND f.fingerprint = v.fp
		  AND (f.template_digest, f.template_path, f.templates_version, f.templates_digest,
		       f.rule_source, f.custom_template_id, f.custom_template_version)
		      IS DISTINCT FROM
		      (NULLIF(v.td, ''), NULLIF(v.tp, ''), NULLIF(v.tv, ''), NULLIF(v.tsd, ''),
		       CASE WHEN v.rs = 'tenant' OR st.id IS NOT NULL THEN 'tenant'
		                       WHEN v.td <> '' THEN 'platform' END, st.id, st.version)`,
		tenantID.String(), pq.Array(fps), pq.Array(tds), pq.Array(tps), pq.Array(tvs), pq.Array(tsds),
		pq.Array(rss), pq.Array(rids))
	if err != nil {
		return 0, fmt.Errorf("record template sightings: %w", err)
	}
	return res.RowsAffected()
}

// RuleProvenance returns which rules found the finding at its last
// sighting, with the organization's template's current name (the template
// is read in the finding's tenant only; "" when it was deleted).
func (r *FindingRepository) RuleProvenance(ctx context.Context, tenantID, findingID shared.ID) (vulnerability.RuleProvenance, error) {
	var src, tid, tver, tname sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT f.rule_source, f.custom_template_id::text, f.custom_template_version, t.name
		FROM findings f
		LEFT JOIN scanner_templates t ON t.id = f.custom_template_id AND t.tenant_id = f.tenant_id
		WHERE f.tenant_id = $1 AND f.id = $2`,
		tenantID.String(), findingID.String()).Scan(&src, &tid, &tver, &tname)
	if errors.Is(err, sql.ErrNoRows) {
		return vulnerability.RuleProvenance{}, shared.ErrNotFound
	}
	if err != nil {
		return vulnerability.RuleProvenance{}, fmt.Errorf("read rule provenance: %w", err)
	}
	return vulnerability.RuleProvenance{Source: src.String, TemplateID: tid.String,
		TemplateName: tname.String, TemplateVersion: tver.String}, nil
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

// MarkCoverageNotObserved marks still-open findings of ids stale
// (observation_state; the status stays):
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
	out, err := r.db.queryIDsWithTransition(ctx, findingTransition{
		Source: "template_drift", Reason: "template_drift", ActorType: "scanner", ActorName: "system: covered scan",
		Message: "A covered scan did not report it, but ran different template content: stale, not fixed",
	}, `
		UPDATE findings f
		SET observation_state = 'stale', updated_at = NOW()
		WHERE f.tenant_id = $1
			AND f.id = ANY($2::uuid[])
			AND f.branch_id IS NULL
			AND f.status IN `+staleFromSQL+`
			AND f.observation_state = 'present'
			AND f.source NOT IN `+coverageProtectedSources+`
		RETURNING f.id::text`, tenantID.String(), pq.Array(idStrs))
	if err != nil {
		return nil, fmt.Errorf("mark coverage findings not observed: %w", err)
	}
	return out, nil
}

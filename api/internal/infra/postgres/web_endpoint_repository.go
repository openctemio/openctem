package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

// WebEndpointRepository stores the web surface sub-inventory
// (web_endpoints, web_endpoint_params). Every query is tenant-scoped.
type WebEndpointRepository struct {
	db *DB
}

// NewWebEndpointRepository creates a WebEndpointRepository.
func NewWebEndpointRepository(db *DB) *WebEndpointRepository {
	return &WebEndpointRepository{db: db}
}

var _ webendpoint.Repository = (*WebEndpointRepository)(nil)

// Record upserts the observations of one origin in one transaction. The
// origin's endpoints are serialized with a transaction-scoped advisory lock,
// so two reports for the same origin cannot both pass the cap.
func (r *WebEndpointRepository) Record(ctx context.Context, tenantID, originAssetID shared.ID,
	obs []webendpoint.Observation, prov webendpoint.Provenance,
) (webendpoint.RecordResult, error) {
	var res webendpoint.RecordResult
	obs = dedupObservations(obs)
	if len(obs) == 0 {
		return res, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7056))`,
		"web_endpoints:"+originAssetID.String()); err != nil {
		return res, fmt.Errorf("lock origin: %w", err)
	}

	hashes := make([]string, len(obs))
	for i, o := range obs {
		hashes[i] = o.TemplateHash
	}
	existing, err := existingTemplates(ctx, tx, tenantID, originAssetID, hashes)
	if err != nil {
		return res, err
	}

	var active, scripts int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE state = 'active'),
			count(*) FILTER (WHERE state = 'active' AND kind = 'script')
		FROM web_endpoints WHERE tenant_id = $1 AND origin_asset_id = $2`,
		tenantID.String(), originAssetID.String()).Scan(&active, &scripts); err != nil {
		return res, fmt.Errorf("count endpoints: %w", err)
	}

	kept := make([]webendpoint.Observation, 0, len(obs))
	for _, o := range obs {
		if existing[o.TemplateHash] {
			kept = append(kept, o)
			res.Updated++
			continue
		}
		if active >= webendpoint.MaxActivePerOrigin || (o.Kind == webendpoint.KindScript && scripts >= webendpoint.MaxScriptsPerOrigin) {
			res.OverCap++
			continue
		}
		active++
		if o.Kind == webendpoint.KindScript {
			scripts++
		}
		kept = append(kept, o)
		res.Created++
	}
	if len(kept) == 0 {
		return res, tx.Commit()
	}

	if err := upsertEndpoints(ctx, tx, tenantID, originAssetID, kept, prov); err != nil {
		return res, err
	}
	ids, err := endpointIDs(ctx, tx, tenantID, originAssetID, kept)
	if err != nil {
		return res, err
	}
	n, err := upsertParams(ctx, tx, tenantID, kept, ids)
	if err != nil {
		return res, err
	}
	res.ParamsOverCap = n
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	return res, nil
}

// dedupObservations merges observations of the same template (the same
// report may name an endpoint twice), keeping the first and joining the
// parameters.
func existingTemplates(ctx context.Context, tx *sql.Tx, tenantID, originAssetID shared.ID, hashes []string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT template_hash FROM web_endpoints
		WHERE tenant_id = $1 AND origin_asset_id = $2 AND template_hash = ANY($3)`,
		tenantID.String(), originAssetID.String(), pq.Array(hashes))
	if err != nil {
		return nil, fmt.Errorf("existing endpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	existing := map[string]bool{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan existing: %w", err)
		}
		existing[h] = true
	}
	return existing, rows.Err()
}

func existingParams(ctx context.Context, tx *sql.Tx, tenantID shared.ID, epIDs []string) (map[string]map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT endpoint_id, location, name FROM web_endpoint_params
		WHERE tenant_id = $1 AND endpoint_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(epIDs))
	if err != nil {
		return nil, fmt.Errorf("existing params: %w", err)
	}
	defer func() { _ = rows.Close() }()
	have := map[string]map[string]bool{}
	for rows.Next() {
		var ep, loc, name string
		if err := rows.Scan(&ep, &loc, &name); err != nil {
			return nil, fmt.Errorf("scan param: %w", err)
		}
		if have[ep] == nil {
			have[ep] = map[string]bool{}
		}
		have[ep][loc+"\x00"+name] = true
	}
	return have, rows.Err()
}

func dedupObservations(obs []webendpoint.Observation) []webendpoint.Observation {
	index := map[string]int{}
	out := make([]webendpoint.Observation, 0, len(obs))
	for _, o := range obs {
		i, ok := index[o.TemplateHash]
		if !ok {
			index[o.TemplateHash] = len(out)
			o.Params = append([]webendpoint.ParamObservation(nil), o.Params...)
			o.Sources = append([]string(nil), o.Sources...)
			out = append(out, o)
			continue
		}
		have := map[string]bool{}
		for _, p := range out[i].Params {
			have[p.Location+"\x00"+p.Name] = true
		}
		for _, p := range o.Params {
			if !have[p.Location+"\x00"+p.Name] && len(out[i].Params) < webendpoint.MaxParamsPerEndpoint {
				out[i].Params = append(out[i].Params, p)
			}
		}
		for _, src := range o.Sources {
			if !slices.Contains(out[i].Sources, src) {
				out[i].Sources = append(out[i].Sources, src)
			}
		}
		out[i].OutOfScope = out[i].OutOfScope || o.OutOfScope
	}
	return out
}

func upsertEndpoints(ctx context.Context, tx *sql.Tx, tenantID, originAssetID shared.ID,
	obs []webendpoint.Observation, prov webendpoint.Provenance,
) error {
	n := len(obs)
	var (
		ids, methods, tmpls, thash, phash, kinds, sources = make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		examples, ctypes, auths, techs, sigs              = make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		statuses                                          = make([]int64, n)
		inScope                                           = make([]bool, n)
		exclusions                                        = make([]string, n)
	)
	for i, o := range obs {
		ids[i] = shared.NewID().String()
		methods[i], tmpls[i], thash[i], phash[i] = o.Method, o.PathTemplate, o.TemplateHash, o.PathHash
		kinds[i], sources[i], examples[i], ctypes[i], auths[i] = o.Kind, strings.Join(o.Sources, ","), o.ExamplePath, o.ContentType, o.AuthState
		techs[i] = strings.Join(o.Technologies, "\x1f")
		sigs[i] = o.ResponseSig()
		statuses[i] = int64(o.StatusCode)
		inScope[i] = !o.OutOfScope
		if o.ExclusionID != nil {
			exclusions[i] = o.ExclusionID.String()
		}
	}
	tool := prov.Tool
	if len(tool) > 64 {
		tool = tool[:64]
	}
	// last_seen_at is bumped at most hourly when nothing else changed, so a
	// re-crawl of a stable site does not rewrite every row.
	_, err := tx.ExecContext(ctx, `
		INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash,
			kind, sources, example_path, last_status, content_type, auth_state, technologies, response_sig, in_scope,
			last_run_id, last_sensor_id, last_tool, exclusion_id)
		SELECT u.id::uuid, $1::uuid, $2::uuid, u.method, u.tmpl, u.thash, u.phash,
			u.kind, string_to_array(u.source, ','), NULLIF(u.example, ''), NULLIF(u.status, 0)::smallint, NULLIF(u.ctype, ''), u.auth,
			CASE WHEN u.tech = '' THEN '{}'::text[] ELSE string_to_array(u.tech, E'\x1f') END, u.sig, u.in_scope,
			$17::uuid, $18::uuid, NULLIF($19, ''),
			(SELECT x.id FROM scope_exclusions x WHERE x.id = NULLIF(u.excl, '')::uuid AND x.tenant_id = $1::uuid)
		FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[],
			$10::text[], $11::bigint[], $12::text[], $13::text[], $14::text[], $15::text[], $16::bool[], $20::text[])
			AS u(id, method, tmpl, thash, phash, kind, source, example, status, ctype, auth, tech, sig, in_scope, excl)
		ON CONFLICT (tenant_id, origin_asset_id, template_hash) DO UPDATE SET
			sources = CASE WHEN excluded.sources <@ web_endpoints.sources THEN web_endpoints.sources
				ELSE ARRAY(SELECT DISTINCT s FROM unnest(web_endpoints.sources || excluded.sources) s ORDER BY s) END,
			kind = CASE WHEN web_endpoints.kind = 'page' THEN excluded.kind ELSE web_endpoints.kind END,
			last_status = COALESCE(excluded.last_status, web_endpoints.last_status),
			content_type = COALESCE(excluded.content_type, web_endpoints.content_type),
			auth_state = CASE WHEN excluded.auth_state = 'unknown' THEN web_endpoints.auth_state ELSE excluded.auth_state END,
			technologies = CASE WHEN cardinality(excluded.technologies) = 0 THEN web_endpoints.technologies ELSE excluded.technologies END,
			last_changed_at = CASE WHEN web_endpoints.response_sig IS DISTINCT FROM excluded.response_sig
				AND web_endpoints.response_sig IS NOT NULL THEN now() ELSE web_endpoints.last_changed_at END,
			response_sig = excluded.response_sig,
			in_scope = excluded.in_scope,
			exclusion_id = excluded.exclusion_id,
			state = CASE WHEN web_endpoints.state = 'gone' THEN 'active' ELSE web_endpoints.state END,
			last_seen_at = now(),
			last_run_id = COALESCE(excluded.last_run_id, web_endpoints.last_run_id),
			last_sensor_id = COALESCE(excluded.last_sensor_id, web_endpoints.last_sensor_id),
			last_tool = COALESCE(excluded.last_tool, web_endpoints.last_tool)
		WHERE web_endpoints.last_seen_at < now() - interval '1 hour'
			OR web_endpoints.state = 'gone'
			OR web_endpoints.in_scope IS DISTINCT FROM excluded.in_scope
			OR web_endpoints.exclusion_id IS DISTINCT FROM excluded.exclusion_id
			OR web_endpoints.response_sig IS DISTINCT FROM excluded.response_sig
			OR NOT (excluded.sources <@ web_endpoints.sources)`,
		tenantID.String(), originAssetID.String(),
		pq.Array(ids), pq.Array(methods), pq.Array(tmpls), pq.Array(thash), pq.Array(phash),
		pq.Array(kinds), pq.Array(sources), pq.Array(examples), pq.Array(statuses), pq.Array(ctypes),
		pq.Array(auths), pq.Array(techs), pq.Array(sigs), pq.Array(inScope),
		nullID(prov.RunID), nullID(prov.SensorID), tool, pq.Array(exclusions))
	if err != nil {
		return fmt.Errorf("upsert endpoints: %w", err)
	}
	return nil
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func endpointIDs(ctx context.Context, tx *sql.Tx, tenantID, originAssetID shared.ID, obs []webendpoint.Observation) (map[string]string, error) {
	hashes := make([]string, len(obs))
	for i, o := range obs {
		hashes[i] = o.TemplateHash
	}
	rows, err := tx.QueryContext(ctx, `SELECT template_hash, id FROM web_endpoints
		WHERE tenant_id = $1 AND origin_asset_id = $2 AND template_hash = ANY($3)`,
		tenantID.String(), originAssetID.String(), pq.Array(hashes))
	if err != nil {
		return nil, fmt.Errorf("endpoint ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]string, len(obs))
	for rows.Next() {
		var h, id string
		if err := rows.Scan(&h, &id); err != nil {
			return nil, fmt.Errorf("scan endpoint id: %w", err)
		}
		out[h] = id
	}
	return out, rows.Err()
}

// upsertParams writes the parameter names of the endpoints, refusing new
// ones beyond MaxParamsPerEndpoint, and refreshes each endpoint's
// param_count. It returns the parameters refused.
func upsertParams(ctx context.Context, tx *sql.Tx, tenantID shared.ID, obs []webendpoint.Observation, ids map[string]string) (int, error) {
	epIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		epIDs = append(epIDs, id)
	}
	have, err := existingParams(ctx, tx, tenantID, epIDs)
	if err != nil {
		return 0, err
	}

	var (
		refused                                     int
		pEp, pLoc, pName, pHint, pRisk, pSens, pSrc []string
		pReq                                        []bool
	)
	for _, o := range obs {
		ep, ok := ids[o.TemplateHash]
		if !ok {
			continue
		}
		for _, p := range o.Params {
			key := p.Location + "\x00" + p.Name
			if !have[ep][key] {
				if len(have[ep]) >= webendpoint.MaxParamsPerEndpoint {
					refused++
					continue
				}
				if have[ep] == nil {
					have[ep] = map[string]bool{}
				}
				have[ep][key] = true
			}
			pEp, pLoc, pName = append(pEp, ep), append(pLoc, p.Location), append(pName, p.Name)
			pHint, pRisk = append(pHint, p.TypeHint), append(pRisk, strings.Join(p.RiskHints, ","))
			pSens, pSrc, pReq = append(pSens, p.Sensitive), append(pSrc, firstOr(o.Sources)), append(pReq, p.Required)
		}
	}
	if len(pEp) > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO web_endpoint_params (tenant_id, endpoint_id, location, name, type_hint, required, risk_hints, sensitive, sources)
			SELECT $1::uuid, u.ep::uuid, u.loc, u.name, NULLIF(u.hint, ''), u.req,
				CASE WHEN u.risk = '' THEN '{}'::text[] ELSE string_to_array(u.risk, ',') END,
				NULLIF(u.sens, ''), ARRAY[u.src]
			FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::bool[], $7::text[], $8::text[], $9::text[])
				AS u(ep, loc, name, hint, req, risk, sens, src)
			ON CONFLICT (endpoint_id, location, name) DO UPDATE SET
				type_hint = COALESCE(excluded.type_hint, web_endpoint_params.type_hint),
				required = web_endpoint_params.required OR excluded.required,
				sources = CASE WHEN excluded.sources[1] = ANY(web_endpoint_params.sources) THEN web_endpoint_params.sources
					ELSE web_endpoint_params.sources || excluded.sources END,
				last_seen_at = now()
			WHERE web_endpoint_params.tenant_id = excluded.tenant_id
				AND (web_endpoint_params.last_seen_at < now() - interval '1 hour'
					OR NOT (excluded.sources[1] = ANY(web_endpoint_params.sources))
					OR (excluded.type_hint IS NOT NULL AND web_endpoint_params.type_hint IS NULL)
					OR (excluded.required AND NOT web_endpoint_params.required))`,
			tenantID.String(), pq.Array(pEp), pq.Array(pLoc), pq.Array(pName), pq.Array(pHint),
			pq.Array(pReq), pq.Array(pRisk), pq.Array(pSens), pq.Array(pSrc)); err != nil {
			return refused, fmt.Errorf("upsert params: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE web_endpoints e SET param_count = LEAST(c.n, 32767)
		FROM (SELECT p.endpoint_id, count(*) AS n FROM web_endpoint_params p
			WHERE p.tenant_id = $1 AND p.endpoint_id = ANY($2::uuid[]) GROUP BY p.endpoint_id) c
		WHERE e.tenant_id = $1 AND e.id = c.endpoint_id AND e.param_count <> c.n`,
		tenantID.String(), pq.Array(epIDs)); err != nil {
		return refused, fmt.Errorf("param counts: %w", err)
	}
	return refused, nil
}

package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// finding_web_locations (docs/architecture/web-surface.md, "Findings on a
// path"): the method, parameter name, status and web endpoint of a finding.

// webLocationSQL upserts one chunk. $1 is the tenant; every other input is
// a parallel array. The endpoint is read with the same tenant id: a hash or
// an origin id that belongs to another tenant matches no row, so a link
// never crosses tenants. The origin is the one the report resolved, else
// the finding's own asset. An exact-method endpoint wins over the ANY one.
//
// A re-sighting keeps what is stored where it brings nothing (a producer that
// stops reporting the method never erases it); the status is the latest one.
const webLocationSQL = `
WITH input AS (
	SELECT * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int[], $7::text[], $8::text[], $9::text[])
		AS i(fp, method, ploc, pname, status, origin, h_exact, h_any)
), resolved AS (
	SELECT f.tenant_id, f.id AS finding_id, NULLIF(i.method, '') AS method, NULLIF(i.ploc, '') AS ploc,
	       NULLIF(i.pname, '') AS pname, NULLIF(i.status, 0)::smallint AS status,
	       (SELECT e.id FROM web_endpoints e
	         WHERE e.tenant_id = f.tenant_id
	           AND e.origin_asset_id = COALESCE(NULLIF(i.origin, '')::uuid, f.asset_id)
	           AND e.template_hash IN (i.h_exact, i.h_any) AND i.h_exact <> ''
	         ORDER BY (e.template_hash = i.h_exact) DESC LIMIT 1) AS endpoint_id
	FROM input i
	JOIN findings f ON f.tenant_id = $1 AND f.fingerprint = i.fp
)
INSERT INTO finding_web_locations (tenant_id, finding_id, method, param_location, param_name, status_code, endpoint_id)
SELECT tenant_id, finding_id, method, ploc, pname, status, endpoint_id FROM resolved
ON CONFLICT (tenant_id, finding_id) DO UPDATE SET
	method         = COALESCE(finding_web_locations.method, EXCLUDED.method),
	param_location = COALESCE(finding_web_locations.param_location, EXCLUDED.param_location),
	param_name     = COALESCE(finding_web_locations.param_name, EXCLUDED.param_name),
	status_code    = COALESCE(EXCLUDED.status_code, finding_web_locations.status_code),
	endpoint_id    = COALESCE(EXCLUDED.endpoint_id, finding_web_locations.endpoint_id),
	updated_at     = now()`

// StoreWebLocations stores the web location of each sighted finding of the
// tenant, matched by fingerprint. Sightings of a finding the tenant does not
// have are skipped.
func (r *FindingRepository) StoreWebLocations(ctx context.Context, tenantID shared.ID, updates []vulnerability.WebLocationUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	last := make(map[string]vulnerability.WebLocationUpdate, len(updates))
	for _, u := range updates {
		last[u.Fingerprint] = u
	}
	list := make([]vulnerability.WebLocationUpdate, 0, len(last))
	for _, u := range last {
		list = append(list, u)
	}
	sortByFingerprint(list, func(u vulnerability.WebLocationUpdate) string { return u.Fingerprint })
	for start := 0; start < len(list); start += maxInteropBatch {
		part := list[start:min(start+maxInteropBatch, len(list))]
		n := len(part)
		fp, method, ploc, pname, origin, hx, ha := make([]string, n), make([]string, n), make([]string, n),
			make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		status := make([]int64, n)
		for i, u := range part {
			fp[i], method[i], ploc[i], pname[i], origin[i], hx[i], ha[i] = u.Fingerprint, u.Method, u.ParamLocation,
				u.ParamName, u.OriginAssetID, u.EndpointHash, u.AnyMethodHash
			status[i] = int64(u.StatusCode)
		}
		err := retryWriteConflict(ctx, func() error {
			_, execErr := r.db.ExecContext(ctx, webLocationSQL, tenantID.String(), pq.Array(fp), pq.Array(method),
				pq.Array(ploc), pq.Array(pname), pq.Array(status), pq.Array(origin), pq.Array(hx), pq.Array(ha))
			return execErr
		})
		if err != nil {
			return fmt.Errorf("store finding web locations: %w", err)
		}
	}
	return nil
}

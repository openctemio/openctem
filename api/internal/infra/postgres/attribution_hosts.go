package postgres

// Children follow their host (research/117 F1): a service, a certificate or a
// web endpoint (application) with automatic pending attribution is linked to
// the one host it was seen on, and from then on carries the host's state.
// Links come only from data of the same tenant: a stored relationship
// (exposes: host -> service; serves_certificate: service -> certificate, which
// follows the service's host) or the host part of the child's own name
// (a service "host:port", a URL). A child with more than one candidate host is
// not linked and stays in review on its own.

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LinkChildren links the tenant's unlinked, automatic pending children to
// their host, flattens chains (a child's followers move to its host), and
// gives every linked child its host's state. It returns how many children
// were linked. Idempotent; every statement is tenant-scoped.
func (r *AttributionRepository) LinkChildren(ctx context.Context, tenantID shared.ID) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("link children: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLocalStatementTimeout(ctx, tx, timeoutBatch); err != nil {
		return 0, err
	}
	// Candidate hosts per child: by relationship, or by the host part of the
	// name. A host is a live asset of the tenant with its own record that
	// follows nobody.
	res, err := tx.ExecContext(ctx, `
		WITH child AS (
			-- host_name: the lower-case host a service ("host:port",
			-- "host:port:tcp", "host:port/tcp", "[v6]:port") or a URL names,
			-- as asset.HostOf reads them; NULL for any other name.
			SELECT c.asset_id, ca.asset_type, ca.name, lower(COALESCE(
				substring(ca.name from '^[A-Za-z][A-Za-z0-9+.-]*://\[?([^]/:?#@\[]+)\]?(?:[:/?#]|$)'),
				substring(ca.name from '^\[([^]]+)\]:[0-9]'),
				substring(ca.name from '^([^:/@\[\]]+):[0-9]+([:/]|$)'))) AS host_name
			FROM asset_attributions c
			JOIN assets ca ON ca.id = c.asset_id AND ca.tenant_id = c.tenant_id
			WHERE c.tenant_id = $1
			  AND c.follows_host_id IS NULL
			  AND c.decided_at IS NULL
			  AND c.state IN ('discovered', 'needs_review', 'candidate')
			  AND ca.deleted_at IS NULL
			  AND ca.asset_type IN ('service', 'certificate', 'application')
		), cand AS (
			SELECT ch.asset_id, r.source_asset_id AS host_id
			FROM child ch
			JOIN asset_relationships r ON r.tenant_id = $1 AND r.target_asset_id = ch.asset_id
			WHERE (ch.asset_type = 'service' AND r.relationship_type = 'exposes')
			UNION
			SELECT ch.asset_id, COALESCE(s.follows_host_id, s.asset_id)
			FROM child ch
			JOIN asset_relationships r ON r.tenant_id = $1 AND r.target_asset_id = ch.asset_id
			  AND r.relationship_type = 'serves_certificate'
			JOIN asset_attributions s ON s.tenant_id = $1 AND s.asset_id = r.source_asset_id
			WHERE ch.asset_type = 'certificate'
			UNION
			SELECT ch.asset_id, h.id
			FROM child ch
			JOIN assets h ON h.tenant_id = $1 AND lower(h.name) = ch.host_name AND h.deleted_at IS NULL
			WHERE ch.asset_type IN ('service', 'application') AND ch.host_name IS NOT NULL
			  AND lower(ch.name) <> ch.host_name
		), one AS (
			SELECT cand.asset_id, min(cand.host_id::text)::uuid AS host_id
			FROM cand
			JOIN asset_attributions h ON h.tenant_id = $1 AND h.asset_id = cand.host_id AND h.follows_host_id IS NULL
			JOIN assets ha ON ha.id = h.asset_id AND ha.tenant_id = $1 AND ha.deleted_at IS NULL
			WHERE cand.host_id <> cand.asset_id
			GROUP BY cand.asset_id
			HAVING count(DISTINCT cand.host_id) = 1
		)
		UPDATE asset_attributions c SET follows_host_id = one.host_id, updated_at = now()
		FROM one
		WHERE c.tenant_id = $1 AND c.asset_id = one.asset_id AND c.follows_host_id IS NULL AND c.decided_at IS NULL`,
		tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("link children: %w", err)
	}
	linked, _ := res.RowsAffected()
	// Flatten: whoever followed a child that now follows a host follows the
	// host itself, so a state change cascades in one step.
	if _, err := tx.ExecContext(ctx, `
		UPDATE asset_attributions f SET follows_host_id = c.follows_host_id, updated_at = now()
		FROM asset_attributions c
		WHERE f.tenant_id = $1 AND c.tenant_id = $1
		  AND f.follows_host_id = c.asset_id AND c.follows_host_id IS NOT NULL
		  AND f.asset_id <> c.follows_host_id`, tenantID.String()); err != nil {
		return 0, fmt.Errorf("link children: flatten: %w", err)
	}
	if err := cascadeToChildren(ctx, tx, tenantID, nil); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("link children: %w", err)
	}
	return linked, nil
}

// cascadeToChildren gives the automatic children of the given hosts (all
// the tenant's hosts when hostIDs is nil) their host's state. A child a
// person decided is never touched (its link was cleared by that decision).
func cascadeToChildren(ctx context.Context, q execQuerier, tenantID shared.ID, hostIDs []string) error {
	var hosts any
	if hostIDs != nil {
		if len(hostIDs) == 0 {
			return nil
		}
		hosts = pq.Array(hostIDs)
	}
	if _, err := q.ExecContext(ctx, `
		UPDATE asset_attributions c SET state = h.state, updated_at = now()
		FROM asset_attributions h
		WHERE h.tenant_id = $1 AND c.tenant_id = $1
		  AND ($2::uuid[] IS NULL OR h.asset_id = ANY($2::uuid[]))
		  AND c.follows_host_id = h.asset_id
		  AND c.decided_at IS NULL
		  AND c.state <> h.state`, tenantID.String(), hosts); err != nil {
		return fmt.Errorf("cascade attribution to children: %w", err)
	}
	return nil
}

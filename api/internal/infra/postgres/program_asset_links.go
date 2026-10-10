package postgres

// Program asset provenance (RFC-065 §16.5): asset_program_links records
// which program lists or covers an asset; assets.system_tags and
// assets.program_only are derived from it here and nowhere else.
//
// A program's targets are the tenant assets its entries name, active or
// not (a followed program not yet accepted still lists its targets), minus
// its program exclusions; an ended program has none. An asset is
// program-only while it has a link, was added after its earliest linked
// program was created, and no active entry of the organization's own scope
// (ownership, self-attestation, letter) covers it. One asset per name: an
// asset the organization already had keeps being its own and only gains
// the link and the tags.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// entryMatchesAsset is the scope match of program_assign.go (domain
// patterns, exact names, addresses in ranges) for entry alias e (columns
// target_type, p) and asset alias a.
const entryMatchesAsset = `
	((e.target_type = 'domain' AND e.p LIKE '*.%'
	  AND (lower(a.name) = substr(e.p, 3) OR right(lower(a.name), length(e.p) - 1) = substr(e.p, 2)))
	 OR (e.target_type = 'domain' AND e.p NOT LIKE '*%' AND lower(a.name) = e.p)
	 OR (e.target_type IN ('ip_address', 'cidr') AND pg_input_is_valid(a.name, 'inet')
	     AND pg_input_is_valid(e.p, 'inet') AND a.name::inet <<= e.p::inet))`

const programTargetAssets = `
	WITH prog AS (
		SELECT id FROM bounty_programs WHERE tenant_id = $1 AND id = $2 AND status <> 'ended'
	), entries AS (
		SELECT target_type, lower(pattern) AS p
		FROM scope_targets
		WHERE tenant_id = $1 AND program_id IN (SELECT id FROM prog) AND status IN ('active', 'inactive')
	), excl AS (
		SELECT lower(pattern) AS p
		FROM bounty_program_exclusions
		WHERE tenant_id = $1 AND program_id IN (SELECT id FROM prog) AND target_type = 'domain'
	)
	SELECT a.id
	FROM assets a
	WHERE a.tenant_id = $1
	  AND (EXISTS (SELECT 1 FROM entries e WHERE ` + entryMatchesAsset + `)
	       OR EXISTS (SELECT 1 FROM bounty_program_target_assets ta
	                  WHERE ta.tenant_id = $1 AND ta.program_id IN (SELECT id FROM prog) AND ta.asset_id = a.id))
	  AND NOT EXISTS (
		SELECT 1 FROM excl x
		WHERE (x.p LIKE '*.%' AND (lower(a.name) = substr(x.p, 3) OR right(lower(a.name), length(x.p) - 1) = substr(x.p, 2)))
		   OR lower(a.name) = x.p)`

// syncProgramAssetLinks keeps the program's links equal to its targets and
// recomputes the derived columns of the tenant's assets.
func syncProgramAssetLinks(ctx context.Context, tx *sql.Tx, tenantID, programID string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_program_links (tenant_id, asset_id, program_id, source)
		SELECT $1, t.id, $2,
		       (SELECT CASE scope_source WHEN 'public_feed' THEN 'programfeed'
		                                 WHEN 'file_import' THEN 'program_import'
		                                 ELSE 'program_manual' END
		        FROM bounty_programs WHERE tenant_id = $1 AND id = $2)
		FROM (`+programTargetAssets+`) t
		ON CONFLICT DO NOTHING`, tenantID, programID); err != nil {
		return fmt.Errorf("link program assets: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM asset_program_links
		WHERE tenant_id = $1 AND program_id = $2 AND asset_id NOT IN (`+programTargetAssets+`)`, tenantID, programID); err != nil {
		return fmt.Errorf("unlink program assets: %w", err)
	}
	return recomputeProgramAssetFlags(ctx, tx, tenantID)
}

// recomputeProgramAssetFlags derives system_tags and program_only for the
// tenant's assets from their links.
func recomputeProgramAssetFlags(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if _, err := tx.ExecContext(ctx, `
		WITH tags AS (
			SELECT l.asset_id, array_agg(DISTINCT t ORDER BY t) AS tags, min(p.created_at) AS first_program
			FROM asset_program_links l
			JOIN bounty_programs p ON p.tenant_id = l.tenant_id AND p.id = l.program_id
			CROSS JOIN LATERAL (SELECT
				COALESCE(NULLIF(regexp_replace(lower(p.platform), '[^a-z0-9-]+', '-', 'g'), ''), 'self') AS plat,
				regexp_replace(lower(COALESCE(NULLIF(p.handle, ''), p.name)), '[^a-z0-9-]+', '-', 'g') AS slug) s
			CROSS JOIN LATERAL unnest(ARRAY[
				'bug-bounty',
				'source:' || replace(l.source, '_', '-'),
				'platform:' || s.plat,
				'program:' || s.plat || ':' || s.slug,
				CASE WHEN p.status = 'pending_attestation' THEN 'program-unattested' END]) AS t
			WHERE l.tenant_id = $1 AND t IS NOT NULL
			GROUP BY l.asset_id
		), own AS (
			SELECT target_type, lower(pattern) AS p FROM scope_targets
			WHERE tenant_id = $1 AND program_id IS NULL AND status = 'active'
			  AND (expires_at IS NULL OR expires_at > now())
		)
		UPDATE assets a SET system_tags = tags.tags,
		       program_only = a.created_at >= tags.first_program
		                      AND NOT EXISTS (SELECT 1 FROM own e WHERE `+entryMatchesAsset+`)
		FROM tags
		WHERE a.tenant_id = $1 AND a.id = tags.asset_id`, tenantID); err != nil {
		return fmt.Errorf("derive program asset tags: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE assets a SET system_tags = '{}', program_only = false
		WHERE a.tenant_id = $1 AND (a.system_tags <> '{}' OR a.program_only)
		  AND NOT EXISTS (SELECT 1 FROM asset_program_links l WHERE l.tenant_id = a.tenant_id AND l.asset_id = a.id)`,
		tenantID); err != nil {
		return fmt.Errorf("clear program asset tags: %w", err)
	}
	return nil
}

// ReplaceTargetAssets sets a program's target assets (RFC-065 §16.8) to
// ids (asset id -> item key) and keeps its links and the derived asset
// fields current, in one transaction. Ids that are not the tenant's assets
// are ignored; the program must be the tenant's.
func (r *BountyProgramRepository) ReplaceTargetAssets(ctx context.Context, tenantID, programID shared.ID, ids map[shared.ID]string) error {
	assetIDs := make([]string, 0, len(ids))
	keys := make([]string, 0, len(ids))
	for id, key := range ids {
		if len(key) > 600 {
			key = key[:600]
		}
		if key == "" {
			key = "-"
		}
		assetIDs = append(assetIDs, id.String())
		keys = append(keys, key)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin program targets: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM bounty_programs WHERE tenant_id = $1 AND id = $2)`,
		tenantID.String(), programID.String()).Scan(&ok); err != nil {
		return fmt.Errorf("program targets: %w", err)
	}
	if !ok {
		return bountyprogram.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM bounty_program_target_assets
		WHERE tenant_id = $1 AND program_id = $2 AND NOT (asset_id = ANY($3::uuid[]))`,
		tenantID.String(), programID.String(), pq.Array(assetIDs)); err != nil {
		return fmt.Errorf("drop program targets: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO bounty_program_target_assets (tenant_id, program_id, asset_id, item_key)
		SELECT $1, $2, a.id, t.key
		FROM unnest($3::uuid[], $4::text[]) AS t(id, key)
		JOIN assets a ON a.tenant_id = $1 AND a.id = t.id
		ON CONFLICT (tenant_id, program_id, asset_id) DO UPDATE SET item_key = EXCLUDED.item_key`,
		tenantID.String(), programID.String(), pq.Array(assetIDs), pq.Array(keys)); err != nil {
		return fmt.Errorf("record program targets: %w", err)
	}
	if err := syncProgramAssetLinks(ctx, tx, tenantID.String(), programID.String()); err != nil {
		return err
	}
	return tx.Commit()
}

// ProgramAssetFlagRepository reads the derived program fields of assets; it
// writes nothing (no scope access).
type ProgramAssetFlagRepository struct{ db *DB }

// NewProgramAssetFlagRepository creates the reader.
func NewProgramAssetFlagRepository(db *DB) *ProgramAssetFlagRepository {
	return &ProgramAssetFlagRepository{db: db}
}

// ProgramAssetFlags reads the derived program fields of assets of one
// tenant (only the assets that have any).
func (r *ProgramAssetFlagRepository) ProgramAssetFlags(ctx context.Context, tenantID string, assetIDs []string) (map[string]bountyprogram.AssetFlags, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id::text, system_tags, program_only FROM assets
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND (system_tags <> '{}' OR program_only)`,
		tenantID, pq.Array(assetIDs))
	if err != nil {
		return nil, fmt.Errorf("read program asset flags: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bountyprogram.AssetFlags{}
	for rows.Next() {
		var id string
		var f bountyprogram.AssetFlags
		if err := rows.Scan(&id, pq.Array(&f.SystemTags), &f.ProgramOnly); err != nil {
			return nil, err
		}
		out[id] = f
	}
	return out, rows.Err()
}

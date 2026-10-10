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
	  AND EXISTS (SELECT 1 FROM entries e WHERE ` + entryMatchesAsset + `)
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

// ProgramAssetFlagsFor is ProgramAssetFlags as viewer may see them
// (RFC-065 §15.3): an owner sees every flag; anyone else does not learn of
// a private program they are not a member of. Its program tag is removed,
// and an asset all of whose programs are such loses every program flag (it
// is shown as an ordinary asset; a program-only one is hidden anyway).
func (r *ProgramAssetFlagRepository) ProgramAssetFlagsFor(ctx context.Context, tenantID string, assetIDs []string, viewer shared.ProgramViewer) (map[string]bountyprogram.AssetFlags, error) {
	flags, err := r.ProgramAssetFlags(ctx, tenantID, assetIDs)
	if err != nil || viewer.Owner || len(flags) == 0 {
		return flags, err
	}
	ids := make([]string, 0, len(flags))
	for id := range flags {
		ids = append(ids, id)
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT l.asset_id::text,
		       (p.visibility = 'private' AND NOT EXISTS (
		            SELECT 1 FROM groups g JOIN group_members gm ON gm.group_id = g.id
		            WHERE g.tenant_id = p.tenant_id AND g.id = p.group_id AND g.is_active AND gm.user_id = $3::uuid)) AS hidden,
		       'program:' || COALESCE(NULLIF(regexp_replace(lower(p.platform), '[^a-z0-9-]+', '-', 'g'), ''), 'self') || ':' ||
		           regexp_replace(lower(COALESCE(NULLIF(p.handle, ''), p.name)), '[^a-z0-9-]+', '-', 'g') AS tag
		FROM asset_program_links l
		JOIN bounty_programs p ON p.tenant_id = l.tenant_id AND p.id = l.program_id
		WHERE l.tenant_id = $1 AND l.asset_id = ANY($2::uuid[])`,
		tenantID, pq.Array(ids), viewer.UserID.String())
	if err != nil {
		return nil, fmt.Errorf("read program visibility: %w", err)
	}
	defer func() { _ = rows.Close() }()
	hiddenTags := map[string]map[string]bool{}
	visible := map[string]bool{}
	for rows.Next() {
		var id, tag string
		var hidden bool
		if err := rows.Scan(&id, &hidden, &tag); err != nil {
			return nil, err
		}
		if !hidden {
			visible[id] = true
			continue
		}
		if hiddenTags[id] == nil {
			hiddenTags[id] = map[string]bool{}
		}
		hiddenTags[id][tag] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for id, tags := range hiddenTags {
		if !visible[id] {
			delete(flags, id)
			continue
		}
		f := flags[id]
		kept := make([]string, 0, len(f.SystemTags))
		for _, t := range f.SystemTags {
			if !tags[t] {
				kept = append(kept, t)
			}
		}
		f.SystemTags = kept
		flags[id] = f
	}
	return flags, nil
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

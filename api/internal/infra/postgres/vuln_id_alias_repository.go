package postgres

// Vulnerability id aliases from the signed feed (RFC-043 §17.2).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md

import (
	"context"
	"fmt"
	"math"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

var (
	_ vulnfeed.VulnIDAliasWriter = (*CVECorpusRepository)(nil)
	_ ingest.VulnAliasResolver   = (*CVECorpusRepository)(nil)
)

// vulnIDAliasChunk is the number of entries written per statement.
const vulnIDAliasChunk = 10_000

// ApplyVulnIDAliases replaces the alias map with a full snapshot of one
// version, in one transaction: every entry is upserted, then the entries the
// snapshot no longer lists are removed, unless they are more than
// max(minRemovals, maxRemovalShare of the stored entries): then nothing is
// applied (a truncated or poisoned map must not wipe the aliases).
func (r *CVECorpusRepository) ApplyVulnIDAliases(ctx context.Context, entries []vulnerability.VulnIDAlias, version uint64,
	maxRemovalShare float64, minRemovals int,
) (vulnfeed.VulnIDAliasResult, error) {
	var res vulnfeed.VulnIDAliasResult
	if version == 0 || version > math.MaxInt64 {
		return res, fmt.Errorf("apply vulnerability id aliases: version %d", version)
	}
	v := int64(version) //nolint:gosec // bounded to MaxInt64 above
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin vulnerability id aliases: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var before int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM vuln_id_aliases`).Scan(&before); err != nil {
		return res, fmt.Errorf("count vulnerability id aliases: %w", err)
	}
	for start := 0; start < len(entries); start += vulnIDAliasChunk {
		end := min(start+vulnIDAliasChunk, len(entries))
		ids := make([]string, 0, end-start)
		cves := make([]string, 0, end-start)
		sources := make([]string, 0, end-start)
		for _, e := range entries[start:end] {
			if !e.Valid() {
				continue
			}
			ids, cves, sources = append(ids, e.ID), append(cves, e.CVE), append(sources, e.Source)
		}
		n, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_id_aliases (alias_id, cve_id, source, version, synced_at)
			SELECT u.id, u.cve, u.source, $4, NOW()
			FROM unnest($1::text[], $2::text[], $3::text[]) AS u(id, cve, source)
			ON CONFLICT (alias_id) DO UPDATE SET cve_id = EXCLUDED.cve_id, source = EXCLUDED.source,
				version = EXCLUDED.version, synced_at = EXCLUDED.synced_at`,
			pq.Array(ids), pq.Array(cves), pq.Array(sources), v)
		if err != nil {
			return res, fmt.Errorf("write vulnerability id aliases: %w", err)
		}
		w, _ := n.RowsAffected()
		res.Written += int(w)
	}
	var stale int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM vuln_id_aliases WHERE version < $1`, v).Scan(&stale); err != nil {
		return res, fmt.Errorf("count stale vulnerability id aliases: %w", err)
	}
	limit := max(minRemovals, int(maxRemovalShare*float64(before)))
	if stale > limit {
		return vulnfeed.VulnIDAliasResult{}, fmt.Errorf("vulnerability id alias map would remove %d of %d entries (limit %d): refused", stale, before, limit)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_id_aliases WHERE version < $1`, v); err != nil {
		return res, fmt.Errorf("remove stale vulnerability id aliases: %w", err)
	}
	res.Removed = stale
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit vulnerability id aliases: %w", err)
	}
	return res, nil
}

// ResolveVulnIDAliases returns the CVE each known advisory id aliases.
// Unknown ids are absent from the map.
func (r *CVECorpusRepository) ResolveVulnIDAliases(ctx context.Context, ids []string) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT alias_id, cve_id FROM vuln_id_aliases WHERE alias_id = ANY($1)`, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("resolve vulnerability id aliases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, cve string
		if err := rows.Scan(&id, &cve); err != nil {
			return nil, fmt.Errorf("scan vulnerability id alias: %w", err)
		}
		out[id] = cve
	}
	return out, rows.Err()
}

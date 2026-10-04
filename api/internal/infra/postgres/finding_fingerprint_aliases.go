package postgres

// Finding fingerprint aliases (RFC-043 §6).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
//
// findings.fingerprint is a finding's current key. finding_fingerprints holds
// every key the finding has had: the current one (kept in step by triggers on
// findings) and the ones it gave up through a re-key or a merge. A report that
// still produces an old key lands on the finding that now carries it.
//
// Every statement here is scoped to one tenant, and the table's foreign key
// references findings by (id, tenant_id), so an alias can never resolve to
// another tenant's finding.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fingerprintAliasChunk bounds the array bound to one lookup.
const fingerprintAliasChunk = 1000

// ResolveFingerprintAliases maps each given key that is a FORMER key of a live
// finding of the tenant to that finding's current key. Keys that are some
// finding's current key, and keys nobody had, are absent from the result:
// the caller keeps using them as they are.
func (r *FindingRepository) ResolveFingerprintAliases(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]string, error) {
	out := make(map[string]string)
	if len(fingerprints) == 0 || tenantID.IsZero() {
		return out, nil
	}
	for start := 0; start < len(fingerprints); start += fingerprintAliasChunk {
		end := min(start+fingerprintAliasChunk, len(fingerprints))
		if err := r.resolveFingerprintAliasChunk(ctx, tenantID, fingerprints[start:end], out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r *FindingRepository) resolveFingerprintAliasChunk(ctx context.Context, tenantID shared.ID, fingerprints []string, out map[string]string) error {
	// A key that is some finding's current key belongs to that finding, even
	// when an older finding had it once: the NOT EXISTS keeps the holder.
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.fingerprint, f.fingerprint
		FROM finding_fingerprints a
		JOIN findings f ON f.id = a.finding_id AND f.tenant_id = a.tenant_id
		WHERE a.tenant_id = $1
		  AND a.fingerprint = ANY($2)
		  AND f.fingerprint <> a.fingerprint
		  AND f.fingerprint NOT LIKE 'dup:%'
		  AND NOT EXISTS (
		      SELECT 1 FROM findings h
		      WHERE h.tenant_id = $1 AND h.fingerprint = a.fingerprint)`,
		tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return fmt.Errorf("resolve fingerprint aliases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var alias, current string
		if err := rows.Scan(&alias, &current); err != nil {
			return fmt.Errorf("scan fingerprint alias: %w", err)
		}
		out[alias] = current
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("resolve fingerprint aliases: %w", err)
	}
	return nil
}

// rememberFindingKey records a finding's current key as one of its aliases,
// in tx. The triggers on findings already do this for every insert and
// re-key; a merge calls it as well so a loser's key is kept even for a row
// written before the alias table existed. A key always belongs to the finding
// that holds it, so an alias another finding had is taken over.
func rememberFindingKey(ctx context.Context, tx *sql.Tx, tenantID, findingID string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_fingerprints (tenant_id, fingerprint, finding_id, version)
		SELECT tenant_id, fingerprint, id, fingerprint_version
		FROM findings
		WHERE id = $1 AND tenant_id = $2 AND fingerprint NOT LIKE 'dup:%'
		ON CONFLICT (tenant_id, fingerprint) DO UPDATE
			SET finding_id = EXCLUDED.finding_id, version = EXCLUDED.version`,
		findingID, tenantID); err != nil {
		return fmt.Errorf("remember finding key: %w", err)
	}
	return nil
}

// AdoptFingerprint re-keys the live finding stored under from to the
// versioned key to, with its identity tuple, when the finding has an older
// recipe version and no finding holds to yet. The old key stays an alias
// (trigger). Race-safe: the NOT EXISTS guard and the unique index decide, and
// losing a race is not an error.
func (r *FindingRepository) AdoptFingerprint(ctx context.Context, tenantID shared.ID, from, to string, identityKey []byte, version int) (bool, error) {
	if from == "" || to == "" || from == to || len(identityKey) == 0 || tenantID.IsZero() {
		return false, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE findings
		SET fingerprint = $3, fingerprint_version = $5, identity_key = $4::jsonb, updated_at = NOW()
		WHERE tenant_id = $1 AND fingerprint = $2
		  AND fingerprint_version < $5
		  AND status <> 'duplicate'
		  AND NOT EXISTS (SELECT 1 FROM findings c WHERE c.tenant_id = $1 AND c.fingerprint = $3)`,
		tenantID.String(), from, to, string(identityKey), version)
	if err != nil {
		if isUniqueViolation(err) {
			return false, nil
		}
		return false, fmt.Errorf("adopt versioned fingerprint: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

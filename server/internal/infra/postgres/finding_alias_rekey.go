package postgres

// Re-keys stored findings when the feed's vulnerability id aliases give
// their advisory id a CVE (RFC-043 §17.2, decision D21).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
//
// Only the vulnerability field of the stored tuple changes (vuln for SCA and
// network, rule for DAST), so the rest of the identity is untouched. A free
// CVE key: the finding takes it in place, its advisory key stays an alias
// (the fingerprint trigger records it), so its triage, tickets and history
// stay. A CVE key another live finding of the asset holds: the two are
// linked as the same issue, never merged (decision D14).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/issuelink"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// AliasRekeyReport is the outcome of the alias re-key for one tenant.
type AliasRekeyReport struct {
	TenantID string `json:"tenant_id"`
	Applied  bool   `json:"applied"`
	Scanned  int    `json:"scanned"`
	Rekeyed  int    `json:"rekeyed"`
	Linked   int    `json:"linked"`
	Skipped  int    `json:"skipped"`
}

// Outcomes of one alias re-key.
const (
	aliasRekeyed = "rekeyed"
	aliasLinked  = "linked"
	aliasSkipped = "skipped"
)

type aliasCandidate struct {
	id, fingerprint string
	key             vulnerability.IdentityKey
}

// RekeyVulnAliases re-keys (apply) or plans (dry run) the tenant's findings
// whose key names an advisory id the resolver ties to a CVE. Batched by id,
// idempotent: a second run finds nothing left to change.
func (r *FindingIssueLinkRepository) RekeyVulnAliases(ctx context.Context, tenantID shared.ID, resolver ingest.VulnAliasResolver, apply bool, batch int) (*AliasRekeyReport, error) {
	if batch <= 0 {
		batch = 500
	}
	rep := &AliasRekeyReport{TenantID: tenantID.String(), Applied: apply}
	after := "00000000-0000-0000-0000-000000000000"
	for {
		cands, last, err := r.aliasCandidates(ctx, tenantID, after, batch)
		if err != nil {
			return nil, err
		}
		if last == "" {
			return rep, nil
		}
		after = last
		rep.Scanned += len(cands)
		var ids []string
		for _, c := range cands {
			ids = append(ids, vulnerability.AdvisoryIDsOf(c.key.Field("vuln"), c.key.Field("rule"))...)
		}
		if len(ids) == 0 {
			continue
		}
		aliases, err := resolver.ResolveVulnIDAliases(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, c := range cands {
			nk, _, ok := vulnerability.AliasRekey(c.key, aliases)
			if !ok {
				continue
			}
			outcome, err := r.rekeyAlias(ctx, tenantID, c, nk, apply)
			if err != nil {
				return nil, err
			}
			switch outcome {
			case aliasRekeyed:
				rep.Rekeyed++
			case aliasLinked:
				rep.Linked++
			default:
				rep.Skipped++
			}
		}
	}
}

func (r *FindingIssueLinkRepository) aliasCandidates(ctx context.Context, tenantID shared.ID, after string, limit int) ([]aliasCandidate, string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.fingerprint, f.identity_key FROM findings f
		WHERE f.tenant_id = $1 AND f.id > $2 AND f.status <> 'duplicate' AND f.identity_key IS NOT NULL
		  AND f.identity_key->>'kind' IN ('sca', 'network', 'dast')
		ORDER BY f.id LIMIT $3`, tenantID.String(), after, limit)
	if err != nil {
		return nil, "", fmt.Errorf("list alias candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []aliasCandidate
	last := ""
	for rows.Next() {
		var c aliasCandidate
		var raw []byte
		if err := rows.Scan(&c.id, &c.fingerprint, &raw); err != nil {
			return nil, "", fmt.Errorf("scan alias candidate: %w", err)
		}
		last = c.id
		k, err := vulnerability.ParseIdentityKey(raw)
		if err != nil {
			continue
		}
		c.key = k
		out = append(out, c)
	}
	return out, last, rows.Err()
}

// rekeyAlias moves one finding to its CVE key, or links it to the holder of
// that key. A dry run reads only. Returns "rekeyed", "linked" or "skipped".
func (r *FindingIssueLinkRepository) rekeyAlias(ctx context.Context, tenantID shared.ID, c aliasCandidate, nk vulnerability.IdentityKey, apply bool) (string, error) {
	tenant := tenantID.String()
	newFP := nk.Fingerprint()
	raw, err := vulnerability.MarshalIdentityKey(nk)
	if err != nil || newFP == "" {
		return aliasSkipped, nil //nolint:nilerr // a key that cannot be stored is left as it is
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: !apply})
	if err != nil {
		return "", fmt.Errorf("begin alias re-key: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if apply {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('issue_links:' || $1, 0))`, tenant); err != nil {
			return "", fmt.Errorf("lock issue links: %w", err)
		}
	}
	lock := ""
	if apply {
		lock = " FOR UPDATE"
	}
	var created time.Time
	var asset string
	err = tx.QueryRowContext(ctx, `SELECT created_at, COALESCE(asset_id::text, '') FROM findings
		WHERE tenant_id = $1 AND id = $2 AND fingerprint = $3 AND status <> 'duplicate'`+lock, tenant, c.id, c.fingerprint).Scan(&created, &asset)
	if errors.Is(err, sql.ErrNoRows) {
		return aliasSkipped, nil // changed since it was listed
	}
	if err != nil {
		return "", fmt.Errorf("read finding to re-key: %w", err)
	}
	var holder, holderAsset string
	var holderCreated time.Time
	if apply {
		holder, holderAsset, holderCreated, err = lockKeyHolder(ctx, tx, tenant, newFP, c.id)
	} else {
		holder, holderAsset, holderCreated, err = keyHolder(ctx, tx, tenant, newFP, c.id)
	}
	if err != nil {
		return "", err
	}
	if holder == "" {
		if !apply {
			return aliasRekeyed, nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET fingerprint = $1, identity_key = $2::jsonb, updated_at = NOW()
			WHERE tenant_id = $3 AND id = $4`, newFP, string(raw), tenant, c.id); err != nil {
			return "", fmt.Errorf("re-key finding to its CVE: %w", err)
		}
		return aliasRekeyed, tx.Commit()
	}
	if holderAsset != asset {
		return aliasSkipped, nil
	}
	if !apply {
		return aliasLinked, nil
	}
	primary, member := c.id, holder
	if holderCreated.Before(created) || (holderCreated.Equal(created) && holder < c.id) {
		primary, member = holder, c.id
	}
	made, err := makeIssueLink(ctx, tx, tenant, issuelink.Link{PrimaryID: primary, MemberID: member, Rule: issuelink.RuleVulnAlias})
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit alias link: %w", err)
	}
	if !made {
		return aliasSkipped, nil
	}
	return aliasLinked, nil
}

// keyHolder is lockKeyHolder without the lock (a dry run).
func keyHolder(ctx context.Context, tx *sql.Tx, tenant, key, self string) (string, string, time.Time, error) {
	var id, asset string
	var created time.Time
	err := tx.QueryRowContext(ctx, `
		SELECT f.id, COALESCE(f.asset_id::text, ''), f.created_at FROM findings f
		WHERE f.tenant_id = $1 AND f.id <> $3 AND f.status <> 'duplicate'
		  AND (f.fingerprint = $2 OR f.id = (
		      SELECT a.finding_id FROM finding_fingerprints a WHERE a.tenant_id = $1 AND a.fingerprint = $2))
		ORDER BY (f.fingerprint = $2) DESC
		LIMIT 1`, tenant, key, self).Scan(&id, &asset, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", time.Time{}, nil
	}
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("key holder: %w", err)
	}
	return id, asset, created, nil
}

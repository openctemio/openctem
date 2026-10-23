package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// One-time repair of DAST findings forked by an identity input a producer
// stopped sending (an HTTP method), or split by a template's fixed request
// paths: findings whose repaired keys (vulnerability.RepairDASTKey) are equal
// are one finding. The earliest-created survives with its triage, comments
// and tickets; each other becomes its tombstone through the finding merge
// (status duplicate, duplicate_of, every reference moved, nothing deleted),
// and each merge is audited. Idempotent: a second run finds nothing.

var causeDASTRepair = findingMergeCause{Reason: "dast_identity_repair", Phrase: "by the DAST identity repair", ActorType: "system"}

// DASTRepairMerge is one fold: loser into survivor.
type DASTRepairMerge struct {
	SurvivorID string `json:"survivor_id"`
	LoserID    string `json:"loser_id"`
}

// DASTRepairReport is what one tenant's repair did, or would do.
type DASTRepairReport struct {
	TenantID string            `json:"tenant_id"`
	Applied  bool              `json:"applied"`
	Scanned  int               `json:"scanned"`
	Rekeyed  int               `json:"rekeyed"`
	Merges   []DASTRepairMerge `json:"merges"`
}

type dastRow struct {
	id, fingerprint, asset string
	created                time.Time
	key                    vulnerability.IdentityKey
}

// RepairDAST repairs one tenant's DAST findings. Without apply it only
// reports. Findings are never merged across assets: the asset is part of the
// key.
func (r *FindingRekeyRepository) RepairDAST(ctx context.Context, tenantID shared.ID, foldRules map[string]bool, apply bool) (*DASTRepairReport, error) {
	tenant := tenantID.String()
	rep := &DASTRepairReport{TenantID: tenant, Applied: apply, Merges: []DASTRepairMerge{}}
	list, err := r.listDASTRows(ctx, tenant)
	if err != nil {
		return nil, err
	}
	rep.Scanned = len(list)
	groups := map[string][]dastRow{}
	keys := map[string]vulnerability.IdentityKey{}
	var order []string
	for _, row := range list {
		nk, ok := vulnerability.RepairDASTKey(row.key, foldRules)
		if !ok || nk.Field(vulnerability.IdentityFieldAsset) != row.asset {
			continue
		}
		fp := nk.Fingerprint()
		if _, seen := groups[fp]; !seen {
			order = append(order, fp)
		}
		groups[fp] = append(groups[fp], row)
		keys[fp] = nk
	}
	for _, fp := range order {
		g := groups[fp]
		sort.SliceStable(g, func(a, b int) bool {
			return g[a].created.Before(g[b].created) || (g[a].created.Equal(g[b].created) && g[a].id < g[b].id)
		})
		survivor := g[0]
		if len(g) == 1 && survivor.fingerprint == fp {
			continue
		}
		for _, l := range g[1:] {
			rep.Merges = append(rep.Merges, DASTRepairMerge{SurvivorID: survivor.id, LoserID: l.id})
		}
		if survivor.fingerprint != fp {
			rep.Rekeyed++
		}
		if !apply {
			continue
		}
		if err := r.repairDASTGroup(ctx, tenant, survivor, g[1:], fp, keys[fp]); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// listDASTRows reads the tenant's live DAST findings with a readable key,
// oldest first.
func (r *FindingRekeyRepository) listDASTRows(ctx context.Context, tenant string) ([]dastRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, fingerprint, COALESCE(asset_id::text, ''), created_at, identity_key
		FROM findings
		WHERE tenant_id = $1 AND status <> 'duplicate' AND identity_key->>'kind' = 'dast'
		ORDER BY created_at, id`, tenant)
	if err != nil {
		return nil, fmt.Errorf("list dast findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []dastRow
	for rows.Next() {
		var row dastRow
		var raw []byte
		if err := rows.Scan(&row.id, &row.fingerprint, &row.asset, &row.created, &raw); err != nil {
			return nil, err
		}
		k, err := vulnerability.ParseIdentityKey(raw)
		if err != nil {
			continue
		}
		row.key = k
		out = append(out, row)
	}
	return out, rows.Err()
}

func (r *FindingRekeyRepository) repairDASTGroup(ctx context.Context, tenant string, survivor dastRow, losers []dastRow, fp string, k vulnerability.IdentityKey) error {
	raw, err := vulnerability.MarshalIdentityKey(k)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, l := range losers {
		// Still live and unchanged since it was listed.
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND id IN ($2, $3)
			AND status <> 'duplicate'`, tenant, survivor.id, l.id).Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			continue
		}
		if err := mergeFindingInto(ctx, tx, tenant, survivor.id, l.id, causeDASTRepair); err != nil {
			return err
		}
		meta, _ := json.Marshal(map[string]string{"survivor_id": survivor.id, "loser_id": l.id,
			"loser_fingerprint": l.fingerprint, "reason": causeDASTRepair.Reason})
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
			VALUES (gen_random_uuid(), $1, 'finding.duplicate_marked', 'finding', $2, 'success', 'medium', $3, $4::jsonb, NOW())`,
			tenant, l.id, "Finding merged into "+survivor.id+" by the DAST identity repair", string(meta)); err != nil {
			return fmt.Errorf("audit dast repair: %w", err)
		}
	}
	if survivor.fingerprint != fp {
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET fingerprint = $1, identity_key = $2::jsonb, updated_at = NOW(),
			       identity_algo = $5, identity_fields = $6
			WHERE tenant_id = $3 AND id = $4 AND status <> 'duplicate'
			  AND NOT EXISTS (SELECT 1 FROM findings c WHERE c.tenant_id = $3 AND c.fingerprint = $1 AND c.id <> $4)`,
			append([]any{fp, string(raw), tenant, survivor.id}, identityKeyRecipeArgs(raw)...)...); err != nil {
			return fmt.Errorf("re-key repaired dast finding: %w", err)
		}
	}
	return tx.Commit()
}

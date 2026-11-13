package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// The practice columns of the findings table (migration finding_practice,
// docs/architecture/finding-practices.md): the program that triages a
// finding and the code of the rule that set it. Derived in Go
// (vulnerability.DerivePractice) right before every insert, from the
// finding's own fields and its asset's facts (derivePractices).
const findingPracticeColumnsSQL = `practice, practice_reason`

// findingPracticeColumnCount is the number of columns in findingPracticeColumnsSQL.
const findingPracticeColumnCount = 2

func findingPracticeArgs(f *vulnerability.Finding) []any {
	return []any{f.Practice().String(), nullString(clip(f.PracticeReason(), vulnerability.MaxPracticeReasonLen))}
}

// findingPracticeConflictSQL is the ON CONFLICT ... DO UPDATE part. The
// stored practice was derived from the stored source, which a re-sighting
// never changes, so it stays, except:
//   - a closed finding keeps its practice (forward only, so closed-period
//     metrics never move);
//   - a row never derived (written before the column existed) takes the
//     incoming derivation;
//   - a re-sighting that changes the finding type (the type upsert takes a
//     non-vulnerability incoming type) takes the incoming derivation, which
//     was made from that type.
func findingPracticeConflictSQL() string {
	return `,
			practice = CASE
				WHEN NOT is_open_finding_status(findings.status) THEN findings.practice
				WHEN findings.practice_reason IS NULL THEN EXCLUDED.practice
				WHEN EXCLUDED.finding_type <> 'vulnerability' AND EXCLUDED.finding_type IS DISTINCT FROM findings.finding_type THEN EXCLUDED.practice
				ELSE findings.practice END,
			practice_reason = CASE
				WHEN NOT is_open_finding_status(findings.status) THEN findings.practice_reason
				WHEN findings.practice_reason IS NULL THEN EXCLUDED.practice_reason
				WHEN EXCLUDED.finding_type <> 'vulnerability' AND EXCLUDED.finding_type IS DISTINCT FROM findings.finding_type THEN EXCLUDED.practice_reason
				ELSE findings.practice_reason END`
}

// findingPracticePlaceholders is ", $first, …" for the practice columns of a
// hand-numbered single-row INSERT.
func findingPracticePlaceholders(first int) string {
	out := ""
	for i := 0; i < findingPracticeColumnCount; i++ {
		out += ", " + placeholder(first+i)
	}
	return out
}

// practiceAssetQuerier is the read the asset facts lookup needs (the pool or
// the caller's transaction).
type practiceAssetQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// practiceAssetFactsSQL reads the facts DerivePractice needs of a tenant's
// assets. Pinned to the tenant: an asset id of another tenant reads as no
// asset.
var practiceAssetFactsSQL = `SELECT id, asset_type,
		` + asset.InternetFacingSQL("assets") + ` AS internet_facing
	FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[])`

// LoadPracticeAssetFacts returns the practice facts of the tenant's assets
// by id (one query). A missing asset is absent from the map.
func LoadPracticeAssetFacts(ctx context.Context, q practiceAssetQuerier, tenantID shared.ID, assetIDs []string) (map[string]vulnerability.PracticeAssetFacts, error) {
	out := make(map[string]vulnerability.PracticeAssetFacts, len(assetIDs))
	if len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, practiceAssetFactsSQL, tenantID.String(), pq.Array(assetIDs))
	if err != nil {
		return nil, fmt.Errorf("read asset facts for practice: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, typ string
		var facing bool
		if err := rows.Scan(&id, &typ, &facing); err != nil {
			return nil, fmt.Errorf("scan asset facts for practice: %w", err)
		}
		out[id] = vulnerability.PracticeAssetFacts{AssetType: typ, AssetInternetFacing: facing}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read asset facts for practice: %w", err)
	}
	return out, nil
}

// derivePractices sets the practice of findings about to be inserted. A
// finding whose caller attached its asset's facts (ingest, which holds the
// assets of the report) is derived from those; the others share one asset
// query per tenant in the batch, and a batch with none sends no query.
func derivePractices(ctx context.Context, q practiceAssetQuerier, findings []*vulnerability.Finding) error {
	byTenant := make(map[shared.ID][]string)
	seen := make(map[string]bool)
	for _, f := range findings {
		if f == nil || f.AssetID().IsZero() {
			continue
		}
		if _, ok := f.AttachedPracticeAssetFacts(); ok {
			continue
		}
		key := f.TenantID().String() + "/" + f.AssetID().String()
		if !seen[key] {
			seen[key] = true
			byTenant[f.TenantID()] = append(byTenant[f.TenantID()], f.AssetID().String())
		}
	}
	facts := make(map[shared.ID]map[string]vulnerability.PracticeAssetFacts, len(byTenant))
	for tid, ids := range byTenant {
		m, err := LoadPracticeAssetFacts(ctx, q, tid, ids)
		if err != nil {
			return err
		}
		facts[tid] = m
	}
	for _, f := range findings {
		if f == nil {
			continue
		}
		af, ok := f.AttachedPracticeAssetFacts()
		if !ok && !f.AssetID().IsZero() {
			af = facts[f.TenantID()][f.AssetID().String()]
		}
		f.ApplyPractice(af)
	}
	return nil
}

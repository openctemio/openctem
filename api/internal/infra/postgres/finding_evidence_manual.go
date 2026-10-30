package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// InsertManual stores recorded request/response records for one finding
// (docs/architecture/finding-evidence.md, "Recorded request/responses"). The
// finding row is locked so two concurrent writes count the same items.
func (r *FindingEvidenceRepository) InsertManual(ctx context.Context, tenantID, findingID shared.ID, recs []evidencedom.NewRecord) (int, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	stored := 0
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM findings WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE`,
			tenantID.String(), findingID.String()).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return evidencedom.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock finding: %w", err)
		}
		held, err := manualEvidenceHashes(ctx, tx, tenantID, findingID)
		if err != nil {
			return err
		}
		fresh := make([]evidencedom.NewRecord, 0, len(recs))
		for _, nr := range recs {
			if held[nr.Record.ContentSHA256] {
				continue
			}
			held[nr.Record.ContentSHA256] = true
			fresh = append(fresh, nr)
		}
		if len(held) > evidencedom.MaxManualPerFinding {
			return evidencedom.ErrTooManyManual
		}
		for _, nr := range fresh {
			nr.Record.FindingID = findingID
			nr.Record.Origin = evidencedom.OriginManual
			if err := insertEvidence(ctx, tx, tenantID, nr); err != nil {
				return err
			}
		}
		stored = len(fresh)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return stored, nil
}

// manualEvidenceHashes returns the content hashes of a finding's manual records.
func manualEvidenceHashes(ctx context.Context, tx *sql.Tx, tenantID, findingID shared.ID) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT content_sha256 FROM finding_evidence
		WHERE tenant_id = $1 AND finding_id = $2 AND origin = $3`,
		tenantID.String(), findingID.String(), string(evidencedom.OriginManual))
	if err != nil {
		return nil, fmt.Errorf("list manual evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()
	held := map[string]bool{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan manual evidence: %w", err)
		}
		held[h] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list manual evidence: %w", err)
	}
	return held, nil
}

type legacyRequestResponses struct {
	tenantID, findingID shared.ID
	entries             []map[string]any
	// version is the finding's evidence version before the move.
	version int64
}

// MoveLegacyRequestResponses moves request/responses kept in clear in
// findings.metadata into manual evidence records and removes the key, one
// batch per transaction and one savepoint per finding: a finding that fails
// is rolled back alone, skipped (logged by the caller from the count, never
// with its values) and the batch goes on. The scan is keyset-paged (after is
// the last id of the previous batch) so a skipped finding is not read again.
// A maintenance job across tenants by design: each finding's records are
// stored under the tenant the finding row holds, and the row is updated
// pinned to that tenant.
func (r *FindingEvidenceRepository) MoveLegacyRequestResponses(ctx context.Context, batch int, after string, convert evidencedom.LegacyConverter) (evidencedom.LegacyMoveResult, error) {
	var res evidencedom.LegacyMoveResult
	if after == "" {
		after = "00000000-0000-0000-0000-000000000000"
	}
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		res = evidencedom.LegacyMoveResult{}
		if err := setLocalStatementTimeout(ctx, tx, timeoutBatch); err != nil {
			return err
		}
		pending, err := lockLegacyRequestResponses(ctx, tx, batch, after)
		if err != nil {
			return err
		}
		for _, p := range pending {
			res.Last = p.findingID.String()
			if err := moveOneLegacy(ctx, tx, p, convert); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				res.Skipped++
				continue
			}
			res.Moved++
		}
		return nil
	})
	if err != nil {
		return evidencedom.LegacyMoveResult{}, err
	}
	return res, nil
}

// moveOneLegacy stores and drops one finding's legacy entries inside a
// savepoint; on error the savepoint is rolled back and the error returned.
func moveOneLegacy(ctx context.Context, tx *sql.Tx, p legacyRequestResponses, convert evidencedom.LegacyConverter) error {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT legacy_rr`); err != nil {
		return err
	}
	err := func() error {
		for _, nr := range convert(ctx, p.tenantID, p.findingID, p.entries) {
			nr.Record.FindingID = p.findingID
			nr.Record.Origin = evidencedom.OriginManual
			if err := insertEvidence(ctx, tx, p.tenantID, nr); err != nil {
				return err
			}
		}
		return dropLegacyRequestResponses(ctx, tx, p)
	}()
	if err != nil {
		if _, rerr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT legacy_rr`); rerr != nil {
			return rerr
		}
		return err
	}
	_, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT legacy_rr`)
	return err
}

func lockLegacyRequestResponses(ctx context.Context, tx *sql.Tx, batch int, after string) ([]legacyRequestResponses, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT tenant_id, id, metadata->'request_responses', evidence_version
		FROM findings
		WHERE metadata ? 'request_responses' AND id > $2::uuid
		ORDER BY id
		LIMIT $1
		FOR NO KEY UPDATE SKIP LOCKED`, batch, after)
	if err != nil {
		return nil, fmt.Errorf("select legacy request/responses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []legacyRequestResponses
	for rows.Next() {
		var tid, fid string
		var raw []byte
		var version int64
		if err := rows.Scan(&tid, &fid, &raw, &version); err != nil {
			return nil, fmt.Errorf("scan legacy request/responses: %w", err)
		}
		p := legacyRequestResponses{version: version}
		if p.tenantID, err = shared.IDFromString(tid); err != nil {
			return nil, fmt.Errorf("legacy request/responses tenant: %w", err)
		}
		if p.findingID, err = shared.IDFromString(fid); err != nil {
			return nil, fmt.Errorf("legacy request/responses finding: %w", err)
		}
		// Anything but a list of objects holds nothing to move; the key is
		// still removed.
		var list []any
		if json.Unmarshal(raw, &list) == nil {
			for _, e := range list {
				if m, ok := e.(map[string]any); ok {
					p.entries = append(p.entries, m)
				}
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// dropLegacyRequestResponses removes the key. Moving storage is not a change
// of the finding a concurrent editor must lose to (row_version stays), and
// a write-up that was current stays current (its evidence version follows
// the records just added).
func dropLegacyRequestResponses(ctx context.Context, tx *sql.Tx, p legacyRequestResponses) error {
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.findings_keep_row_version', 'on', true)`); err != nil {
		return fmt.Errorf("keep row version: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE findings SET metadata = (metadata - 'request_responses') ||
			CASE WHEN jsonb_typeof(metadata->'writeup_evidence_version') = 'number'
			          AND (metadata->>'writeup_evidence_version')::numeric = $3
			     THEN jsonb_build_object('writeup_evidence_version', evidence_version)
			     ELSE '{}'::jsonb END
		WHERE tenant_id = $1 AND id = $2`,
		p.tenantID.String(), p.findingID.String(), p.version)
	if err != nil {
		return fmt.Errorf("drop legacy request/responses: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("drop legacy request/responses: finding %s not updated", p.findingID.String())
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.findings_keep_row_version', 'off', true)`); err != nil {
		return fmt.Errorf("restore row version: %w", err)
	}
	return nil
}

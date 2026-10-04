package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/credential"
)

// credentialSecretBackfillBatch bounds how many rows one transaction rewrites.
const credentialSecretBackfillBatch = 200

// BackfillLeakedCredentialSecrets seals every leaked-credential secret that is
// still stored in plaintext: rows written before secrets were encrypted
// (details.secret_value) and, once APP_ENCRYPTION_KEY is configured, rows
// written without a key (details.secret_enc_scheme = 'none').
//
// It is idempotent and safe to run concurrently with itself and with live
// traffic: each batch locks its rows with FOR UPDATE SKIP LOCKED, re-checks
// them in Go, and a sealed row no longer matches the selection. It returns the
// number of rows rewritten.
func BackfillLeakedCredentialSecrets(ctx context.Context, db *sql.DB, p *credential.SecretProtector) (int, error) {
	total := 0
	for {
		n, err := backfillCredentialSecretBatch(ctx, db, p)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
}

func backfillCredentialSecretBatch(ctx context.Context, db *sql.DB, p *credential.SecretProtector) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin credential secret backfill: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	batch, err := selectPlaintextSecrets(ctx, tx, p.Encrypts())
	if err != nil {
		return 0, err
	}

	updated := 0
	for _, row := range batch {
		if !p.NeedsSealing(row.details) {
			continue
		}
		if err := p.Seal(row.details); err != nil {
			return 0, fmt.Errorf("seal secret of exposure %s: %w", row.id, err)
		}
		raw, err := json.Marshal(row.details)
		if err != nil {
			return 0, fmt.Errorf("encode details of exposure %s: %w", row.id, err)
		}
		// updated_at is left alone: sealing does not change what the row says.
		// The row is pinned to the tenant it was read with.
		if _, err := tx.ExecContext(ctx, `UPDATE exposure_events SET details = $1 WHERE id = $2 AND tenant_id = $3`, raw, row.id, row.tenantID); err != nil {
			return 0, fmt.Errorf("update exposure %s: %w", row.id, err)
		}
		updated++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit credential secret backfill: %w", err)
	}
	return updated, nil
}

type pendingSecretRow struct {
	id       string
	tenantID string
	details  map[string]any
}

// selectPlaintextSecrets locks one batch of rows whose secret still needs
// sealing. The 'none' scheme is selected only when this run can encrypt;
// otherwise those rows are already in their final form for this key state.
func selectPlaintextSecrets(ctx context.Context, tx *sql.Tx, canEncrypt bool) ([]pendingSecretRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, tenant_id, details
		FROM exposure_events
		WHERE COALESCE(details->>'secret_value', '') <> ''
		   OR ($1 AND details->>'secret_enc_scheme' = 'none')
		ORDER BY id
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, canEncrypt, credentialSecretBackfillBatch)
	if err != nil {
		return nil, fmt.Errorf("select plaintext credential secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var batch []pendingSecretRow
	for rows.Next() {
		var id, tenantID string
		var raw []byte
		if err := rows.Scan(&id, &tenantID, &raw); err != nil {
			return nil, fmt.Errorf("scan credential secret row: %w", err)
		}
		details := map[string]any{}
		if err := json.Unmarshal(raw, &details); err != nil {
			return nil, fmt.Errorf("decode details of exposure %s: %w", id, err)
		}
		batch = append(batch, pendingSecretRow{id: id, tenantID: tenantID, details: details})
	}
	return batch, rows.Err()
}

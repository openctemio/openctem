package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/credential"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// credentialFingerprintRekeyBatch bounds how many rows one transaction rewrites.
const credentialFingerprintRekeyBatch = 200

// CredentialFingerprintRekeyReport counts what one re-key (or reversal) run did.
type CredentialFingerprintRekeyReport struct {
	// Rekeyed rows got the fingerprint of the wanted recipe.
	Rekeyed int
	// Unrecomputable rows keep their fingerprint: their secret cannot be
	// opened with the configured key, or no value is stored.
	Unrecomputable int
}

// RekeyLeakedCredentialFingerprints moves every leaked-credential secret
// fingerprint written with the install-wide recipe to its organization's
// recipe (credential.SecretProtector.Fingerprint), recomputing it from the
// stored secret.
//
// It is idempotent (a row in the organization recipe carries
// secret_fingerprint_version = 2 and is no longer selected), resumable (each
// batch commits on its own; a restart picks up the rows still in the old
// recipe) and safe across replicas and live traffic: rows are locked FOR
// UPDATE (a row another transaction holds is waited for, then re-checked by
// Postgres against the selection, so a replica never re-keys a row twice or
// skips one), and the UPDATE is pinned to the row's tenant. It only rewrites the two
// fingerprint keys; it never touches the sealed value or any key material.
// The reversal is RevertLeakedCredentialFingerprints.
func RekeyLeakedCredentialFingerprints(ctx context.Context, db *sql.DB, p *credential.SecretProtector) (CredentialFingerprintRekeyReport, error) {
	return walkCredentialFingerprints(ctx, db, false, func(tid shared.ID, d map[string]any) credential.FingerprintOutcome {
		return p.RekeyFingerprint(tid, d)
	})
}

// RevertLeakedCredentialFingerprints puts back the install-wide fingerprint
// on every row the re-key moved, for a rollback to a build that only knows
// that recipe. Same batching and safety as the re-key.
func RevertLeakedCredentialFingerprints(ctx context.Context, db *sql.DB, p *credential.SecretProtector) (CredentialFingerprintRekeyReport, error) {
	return walkCredentialFingerprints(ctx, db, true, func(_ shared.ID, d map[string]any) credential.FingerprintOutcome {
		return p.RevertFingerprint(d)
	})
}

// CountLeakedCredentialFingerprintsToRekey counts the rows a re-key would
// select (a rehearsal's dry run).
func CountLeakedCredentialFingerprintsToRekey(ctx context.Context, db *sql.DB) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM exposure_events WHERE `+credentialFingerprintOldRecipe).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count leaked credential fingerprints: %w", err)
	}
	return n, nil
}

// The selection: rows with a sealed secret and a fingerprint in the old
// recipe (revert: in the organization recipe). Constant SQL, one per
// direction.
const (
	credentialFingerprintOldRecipe = `COALESCE(details->>'secret_value_enc', '') <> ''
		AND COALESCE(details->>'secret_fingerprint', '') <> ''
		AND COALESCE(details->>'secret_fingerprint_version', '') <> '2'`
	credentialFingerprintTenantRecipe = `COALESCE(details->>'secret_value_enc', '') <> ''
		AND COALESCE(details->>'secret_fingerprint', '') <> ''
		AND details->>'secret_fingerprint_version' = '2'`

	selectCredentialFingerprintsOld = `SELECT id, tenant_id, details FROM exposure_events
		WHERE id > $1::uuid AND ` + credentialFingerprintOldRecipe + `
		ORDER BY id LIMIT $2 FOR UPDATE`
	selectCredentialFingerprintsTenant = `SELECT id, tenant_id, details FROM exposure_events
		WHERE id > $1::uuid AND ` + credentialFingerprintTenantRecipe + `
		ORDER BY id LIMIT $2 FOR UPDATE`
)

func walkCredentialFingerprints(ctx context.Context, db *sql.DB, revert bool,
	apply func(shared.ID, map[string]any) credential.FingerprintOutcome) (CredentialFingerprintRekeyReport, error) {
	var rep CredentialFingerprintRekeyReport
	// The cursor moves past rows that cannot be recomputed, so they are
	// reported once per run instead of selected forever.
	cursor := uuidBeforeAll
	for {
		next, n, err := credentialFingerprintBatch(ctx, db, revert, cursor, apply, &rep)
		if err != nil {
			return rep, err
		}
		if n == 0 {
			return rep, nil
		}
		cursor = next
	}
}

func credentialFingerprintBatch(ctx context.Context, db *sql.DB, revert bool, cursor string,
	apply func(shared.ID, map[string]any) credential.FingerprintOutcome, rep *CredentialFingerprintRekeyReport) (string, int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, fmt.Errorf("begin credential fingerprint re-key: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	q := selectCredentialFingerprintsOld
	if revert {
		q = selectCredentialFingerprintsTenant
	}
	rows, err := tx.QueryContext(ctx, q, cursor, credentialFingerprintRekeyBatch)
	if err != nil {
		return "", 0, fmt.Errorf("select leaked credential fingerprints: %w", err)
	}
	batch, err := scanPendingSecretRows(rows)
	if err != nil {
		return "", 0, err
	}

	last := cursor
	for _, row := range batch {
		last = row.id
		tid, err := shared.IDFromString(row.tenantID)
		if err != nil {
			return "", 0, fmt.Errorf("tenant of exposure %s: %w", row.id, err)
		}
		switch apply(tid, row.details) {
		case credential.FingerprintRekeyed:
		case credential.FingerprintUnrecomputable:
			rep.Unrecomputable++
			continue
		default:
			continue
		}
		fp, _ := row.details[credential.DetailSecretFingerprint].(string)
		// Only the fingerprint keys change; updated_at is left alone (what
		// the row says is the same). Pinned to the tenant it was read with.
		var err2 error
		if revert {
			_, err2 = tx.ExecContext(ctx, `UPDATE exposure_events
				SET details = jsonb_set(details, '{secret_fingerprint}', to_jsonb($1::text)) - 'secret_fingerprint_version'
				WHERE id = $2 AND tenant_id = $3`, fp, row.id, row.tenantID)
		} else {
			_, err2 = tx.ExecContext(ctx, `UPDATE exposure_events
				SET details = jsonb_set(jsonb_set(details, '{secret_fingerprint}', to_jsonb($1::text)),
				                        '{secret_fingerprint_version}', to_jsonb($4::int))
				WHERE id = $2 AND tenant_id = $3`, fp, row.id, row.tenantID, credential.FingerprintVersionTenant)
		}
		if err2 != nil {
			return "", 0, fmt.Errorf("update fingerprint of exposure %s: %w", row.id, err2)
		}
		rep.Rekeyed++
	}
	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("commit credential fingerprint re-key: %w", err)
	}
	return last, len(batch), nil
}

// scanPendingSecretRows reads (id, tenant_id, details) rows and closes them.
func scanPendingSecretRows(rows *sql.Rows) ([]pendingSecretRow, error) {
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

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LegacySecretFingerprintCutoff is the default cutoff of
// ClearLegacySecretFingerprints: when the keyed secret fingerprint was
// introduced. A secret finding created earlier carries a fingerprint computed
// from the tenant id alone.
var LegacySecretFingerprintCutoff = time.Date(2026, time.October, 3, 14, 9, 0, 0, time.UTC)

// LegacySecretFingerprintReport is the outcome of one run.
type LegacySecretFingerprintReport struct {
	Applied bool
	// Matched is the number of findings holding a legacy fingerprint (a dry
	// run counts them; an applied run counts the ones it cleared).
	Matched int
	// Remaining is what an applied run could not clear because another
	// transaction held the row; run it again.
	Remaining int
}

// ClearLegacySecretFingerprints removes type_details.secret.fingerprint from
// the findings created before cutoff (optionally of one tenant). Those values
// were computed from the tenant id alone, so they cannot be verified and
// confirm a guessed secret offline. A finding only gains a fingerprint while
// it has none (Finding.EnrichFrom), so the next sighting writes the keyed
// value. Nothing else on the finding changes.
//
// It runs in batches of batchSize rows, each its own short statement that
// skips rows another transaction holds, so no long lock is taken. A dry run
// (apply false) only counts.
func ClearLegacySecretFingerprints(ctx context.Context, db *sql.DB, tenantID *shared.ID, cutoff time.Time, apply bool, batchSize int) (*LegacySecretFingerprintReport, error) {
	if batchSize <= 0 {
		return nil, fmt.Errorf("batch size must be positive")
	}
	var tenant any
	if tenantID != nil {
		tenant = tenantID.String()
	}
	rep := &LegacySecretFingerprintReport{Applied: apply}
	if !apply {
		err := db.QueryRowContext(ctx, legacySecretFingerprintCount, tenant, cutoff).Scan(&rep.Matched)
		return rep, err
	}
	for {
		res, err := db.ExecContext(ctx, `
			WITH batch AS (
				SELECT id FROM findings
				WHERE `+legacySecretFingerprintWhere+`
				LIMIT $3
				FOR UPDATE SKIP LOCKED
			)
			UPDATE findings f SET type_details = f.type_details #- '{secret,fingerprint}'
			FROM batch WHERE f.id = batch.id`, tenant, cutoff, batchSize)
		if err != nil {
			return rep, fmt.Errorf("clear legacy secret fingerprints: %w", err)
		}
		n, _ := res.RowsAffected()
		rep.Matched += int(n)
		if int(n) < batchSize {
			break
		}
	}
	if err := db.QueryRowContext(ctx, legacySecretFingerprintCount, tenant, cutoff).Scan(&rep.Remaining); err != nil {
		return rep, err
	}
	return rep, nil
}

const legacySecretFingerprintWhere = `($1::uuid IS NULL OR tenant_id = $1::uuid)
				  AND created_at < $2
				  AND COALESCE(type_details->'secret'->>'fingerprint', '') <> ''`

const legacySecretFingerprintCount = `SELECT COUNT(*) FROM findings WHERE ` + legacySecretFingerprintWhere

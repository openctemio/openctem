package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/subscription"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/licensekey"
)

// SubscriptionRepository stores the installation's licenses
// (subscription_licenses) and its license state row (subscription_state).
// Installation-wide tables with no tenant data
// (docs/rfcs/RFC-145-enterprise-license-and-entitlements.md); every stored
// file is re-verified by the subscription service when it is loaded.
type SubscriptionRepository struct {
	db *DB
}

// NewSubscriptionRepository creates the repository.
func NewSubscriptionRepository(db *DB) *SubscriptionRepository {
	return &SubscriptionRepository{db: db}
}

var _ subscription.Repository = (*SubscriptionRepository)(nil)

const subscriptionStateQuery = `SELECT installation_id::text, time_high_water, keyset_high_water,
	revoked_license_ids, revoked_key_ids, version FROM subscription_state WHERE singleton`

// State returns the state row.
func (r *SubscriptionRepository) State(ctx context.Context) (subscription.State, error) {
	var (
		st        subscription.State
		ksVersion int64
		lic, keys pq.StringArray
	)
	err := r.db.QueryRowContext(ctx, subscriptionStateQuery).Scan(&st.InstallationID, &st.TimeHighWater, &ksVersion, &lic, &keys, &st.Version)
	if err != nil {
		return subscription.State{}, fmt.Errorf("read license state: %w", err)
	}
	if ksVersion < 0 {
		return subscription.State{}, errors.New("read license state: negative key-set version")
	}
	st.KeySetHighWater = uint64(ksVersion)
	st.Revoked = licensekey.Revocations{LicenseIDs: lic, KeyIDs: keys}
	return st, nil
}

// Version returns the state row's version.
func (r *SubscriptionRepository) Version(ctx context.Context) (int64, error) {
	var v int64
	if err := r.db.QueryRowContext(ctx, `SELECT version FROM subscription_state WHERE singleton`).Scan(&v); err != nil {
		return 0, fmt.Errorf("read license state version: %w", err)
	}
	return v, nil
}

// List returns up to limit licenses, newest first, removed ones included.
func (r *SubscriptionRepository) List(ctx context.Context, limit int) ([]subscription.Record, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, license_id, customer_id, license_type, licensee_name, issued_at,
		not_before, expires_at, grace_days, entitlements, keyset_version, signing_key_id, file, source,
		added_by, added_at, removed_by, removed_at
		FROM subscription_licenses ORDER BY added_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list licenses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []subscription.Record
	for rows.Next() {
		var (
			rec                subscription.Record
			id                 string
			typ, src           string
			ents               pq.StringArray
			ksVersion          int64
			addedBy, removedBy sql.NullString
			removedAt          sql.NullTime
		)
		if err := rows.Scan(&id, &rec.LicenseID, &rec.CustomerID, &typ, &rec.LicenseeName, &rec.IssuedAt,
			&rec.NotBefore, &rec.ExpiresAt, &rec.GraceDays, &ents, &ksVersion, &rec.SigningKeyID, &rec.File, &src,
			&addedBy, &rec.AddedAt, &removedBy, &removedAt); err != nil {
			return nil, fmt.Errorf("scan license: %w", err)
		}
		if rec.ID, err = shared.IDFromString(id); err != nil {
			return nil, fmt.Errorf("scan license: %w", err)
		}
		rec.Type, rec.Source = licensekey.Type(typ), subscription.Source(src)
		if ksVersion > 0 {
			rec.KeySetVersion = uint64(ksVersion)
		}
		for _, e := range ents {
			rec.Entitlements = append(rec.Entitlements, limits.GrantKey(e))
		}
		rec.AddedBy, rec.RemovedBy = subscriptionOptionalID(addedBy), subscriptionOptionalID(removedBy)
		if removedAt.Valid {
			t := removedAt.Time
			rec.RemovedAt = &t
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func subscriptionOptionalID(s sql.NullString) *shared.ID {
	if !s.Valid {
		return nil
	}
	id, err := shared.IDFromString(s.String)
	if err != nil {
		return nil
	}
	return &id
}

func subscriptionIDArg(id *shared.ID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

// Add stores rec and, in the same transaction, raises the key-set
// high-water mark, adds the revocations and bumps the version.
func (r *SubscriptionRepository) Add(ctx context.Context, rec subscription.Record, keySetVersion uint64, revoked licensekey.Revocations) error {
	if keySetVersion > math.MaxInt64 || rec.KeySetVersion > math.MaxInt64 {
		return fmt.Errorf("%w: key-set version out of range", shared.ErrValidation)
	}
	ents := make([]string, 0, len(rec.Entitlements))
	for _, e := range rec.Entitlements {
		ents = append(ents, string(e))
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("add license: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// The state row is locked first so concurrent adds run one at a time.
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM subscription_state WHERE singleton FOR UPDATE`); err != nil {
		return fmt.Errorf("add license: lock state: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO subscription_licenses (id, license_id, customer_id, license_type,
		licensee_name, issued_at, not_before, expires_at, grace_days, entitlements, keyset_version, signing_key_id,
		file, source, added_by, added_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		rec.ID.String(), rec.LicenseID, rec.CustomerID, string(rec.Type), rec.LicenseeName, rec.IssuedAt,
		rec.NotBefore, rec.ExpiresAt, rec.GraceDays, pq.StringArray(ents), int64(rec.KeySetVersion), //nolint:gosec // bounded above
		rec.SigningKeyID, rec.File, string(rec.Source), subscriptionIDArg(rec.AddedBy), rec.AddedAt)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return subscription.ErrAlreadyStored
		}
		return fmt.Errorf("add license: %w", err)
	}
	// Revocations are only ever added (a later file cannot un-revoke).
	_, err = tx.ExecContext(ctx, `UPDATE subscription_state SET
		keyset_high_water = GREATEST(keyset_high_water, $1),
		revoked_license_ids = ARRAY(SELECT DISTINCT unnest(revoked_license_ids || $2::text[]) ORDER BY 1),
		revoked_key_ids = ARRAY(SELECT DISTINCT unnest(revoked_key_ids || $3::text[]) ORDER BY 1),
		version = version + 1, updated_at = now()
		WHERE singleton`,
		int64(keySetVersion), pq.StringArray(revoked.LicenseIDs), pq.StringArray(revoked.KeyIDs)) //nolint:gosec // bounded above
	if err != nil {
		return fmt.Errorf("add license: update state: %w", err)
	}
	return tx.Commit()
}

// Remove marks a stored license removed and bumps the version.
func (r *SubscriptionRepository) Remove(ctx context.Context, id shared.ID, by *shared.ID, at time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("remove license: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE subscription_licenses SET removed_at = $2, removed_by = $3
		WHERE id = $1 AND removed_at IS NULL`, id.String(), at, subscriptionIDArg(by))
	if err != nil {
		return fmt.Errorf("remove license: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return subscription.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE subscription_state SET version = version + 1, updated_at = now() WHERE singleton`); err != nil {
		return fmt.Errorf("remove license: update state: %w", err)
	}
	return tx.Commit()
}

// AdvanceTimeHighWater raises the time high-water mark; it never lowers it.
func (r *SubscriptionRepository) AdvanceTimeHighWater(ctx context.Context, t time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE subscription_state
		SET time_high_water = GREATEST(time_high_water, $1), updated_at = now() WHERE singleton`, t)
	if err != nil {
		return fmt.Errorf("advance license time high-water mark: %w", err)
	}
	return nil
}

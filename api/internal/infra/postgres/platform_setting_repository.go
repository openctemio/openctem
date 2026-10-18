package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// PlatformSettingRepository stores console settings in platform_settings.
type PlatformSettingRepository struct {
	db *DB
}

// NewPlatformSettingRepository creates the repository.
func NewPlatformSettingRepository(db *DB) *PlatformSettingRepository {
	return &PlatformSettingRepository{db: db}
}

var _ platformsetting.Repository = (*PlatformSettingRepository)(nil)

// Get reads the setting stored under key.
func (r *PlatformSettingRepository) Get(ctx context.Context, key string) (platformsetting.State, error) {
	var (
		st        platformsetting.State
		raw       []byte
		updatedBy sql.NullString
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT value, version, source, updated_by, updated_at FROM platform_settings WHERE key = $1`, key,
	).Scan(&raw, &st.Version, &st.Source, &updatedBy, &st.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return platformsetting.State{}, platformsetting.ErrNotFound
		}
		return platformsetting.State{}, fmt.Errorf("get platform setting: %w", err)
	}
	st.Value = json.RawMessage(raw)
	if updatedBy.Valid {
		if id, perr := shared.IDFromString(updatedBy.String); perr == nil {
			st.UpdatedBy = &id
		}
	}
	return st, nil
}

// CreateIfAbsent stores version 1 unless a row exists.
func (r *PlatformSettingRepository) CreateIfAbsent(ctx context.Context, key string, s platformsetting.State) (bool, error) {
	var by any
	if s.UpdatedBy != nil {
		by = s.UpdatedBy.String()
	}
	source := s.Source
	if source == "" {
		source = platformsetting.SourceConsole
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
		VALUES ($1, $2, 1, $3, $4, $5)
		ON CONFLICT (key) DO NOTHING`,
		key, []byte(s.Value), source, by, s.UpdatedAt,
	)
	if err != nil {
		return false, fmt.Errorf("create platform setting: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n == 1, nil
}

// Update is a compare-and-swap on the version.
func (r *PlatformSettingRepository) Update(ctx context.Context, key string, value json.RawMessage, expectedVersion int, by shared.ID, at time.Time) (platformsetting.State, error) {
	var version int
	err := r.db.QueryRowContext(ctx, `
		UPDATE platform_settings
		   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
		 WHERE key = $1 AND version = $5
		RETURNING version`,
		key, []byte(value), by.String(), at, expectedVersion,
	).Scan(&version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return platformsetting.State{}, platformsetting.ErrVersionConflict
		}
		return platformsetting.State{}, fmt.Errorf("update platform setting: %w", err)
	}
	id := by
	return platformsetting.State{Value: value, Version: version, Source: platformsetting.SourceConsole, UpdatedBy: &id, UpdatedAt: at}, nil
}

// CreateIfAbsentBeforeFirstTenant stores version 1 under key only while no
// setting is stored there and no organization exists. It runs in one
// transaction that holds a SHARE lock on tenants, so an organization created
// at the same moment either commits first (and the setting is refused) or
// waits until the setting is stored (and gets it). It reports whether it
// stored the row and, when it did not, whether organizations exist. The
// platform's system tenant is not an organization.
func (r *PlatformSettingRepository) CreateIfAbsentBeforeFirstTenant(ctx context.Context, key string, s platformsetting.State) (created, tenantsExist bool, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE tenants IN SHARE MODE`); err != nil {
		return false, false, fmt.Errorf("lock tenants: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id <> $1)`, tenant.SystemTenantID).Scan(&tenantsExist); err != nil {
		return false, false, fmt.Errorf("count tenants: %w", err)
	}
	if tenantsExist {
		return false, true, nil
	}
	var by any
	if s.UpdatedBy != nil {
		by = s.UpdatedBy.String()
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
		VALUES ($1, $2, 1, 'console', $3, $4)
		ON CONFLICT (key) DO NOTHING`,
		key, []byte(s.Value), by, s.UpdatedAt,
	)
	if err != nil {
		return false, false, fmt.Errorf("create platform setting: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, false, fmt.Errorf("rows affected: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, false, fmt.Errorf("commit: %w", err)
	}
	return n == 1, false, nil
}

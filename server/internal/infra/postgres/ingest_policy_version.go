package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IngestPolicyVersions reads the per-tenant ingest policy version that the
// triggers on suppression_rules and scope_exclusions bump.
type IngestPolicyVersions struct {
	db *DB
}

// NewIngestPolicyVersions constructs the reader.
func NewIngestPolicyVersions(db *DB) *IngestPolicyVersions { return &IngestPolicyVersions{db: db} }

// PolicyVersion returns the tenant's version, 0 when no policy was written.
func (r *IngestPolicyVersions) PolicyVersion(ctx context.Context, tenantID shared.ID) (int64, error) {
	var v int64
	err := r.db.QueryRowContext(ctx, `SELECT version FROM ingest_policy_versions WHERE tenant_id = $1`, tenantID.String()).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("ingest policy version: %w", err)
	}
	return v, nil
}

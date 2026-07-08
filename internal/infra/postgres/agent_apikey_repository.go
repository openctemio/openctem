package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	agentdom "github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AgentAPIKeyRepository persists per-agent API keys in the agent_api_keys table.
// This is the multi-key model behind rotation overlap (RFC-014 Phase 3): an
// agent can hold several keys at once so a renewed key (N+1) coexists with the
// key it replaces (N) during a grace window, and each key carries its own
// expiry, scopes, and usage audit. It is separate from api_keys (tenant/user
// keys) — a different table and concept.
type AgentAPIKeyRepository struct {
	db *DB
}

// NewAgentAPIKeyRepository creates an AgentAPIKeyRepository.
func NewAgentAPIKeyRepository(db *DB) *AgentAPIKeyRepository {
	return &AgentAPIKeyRepository{db: db}
}

var _ agentdom.APIKeyRepository = (*AgentAPIKeyRepository)(nil)

const agentAPIKeyColumns = `
	id, agent_id, name, key_hash, key_prefix, scopes,
	expires_at, last_used_at, host(last_used_ip), use_count,
	is_active, revoked_at, revoked_reason, created_at`

// Create inserts a new API key.
func (r *AgentAPIKeyRepository) Create(ctx context.Context, key *agentdom.APIKey) error {
	query := `
		INSERT INTO agent_api_keys (
			id, agent_id, name, key_hash, key_prefix, scopes,
			expires_at, last_used_at, last_used_ip, use_count,
			is_active, revoked_at, revoked_reason, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := r.db.ExecContext(ctx, query,
		key.ID.String(),
		key.AgentID.String(),
		key.Name,
		key.KeyHash,
		key.KeyPrefix,
		pq.Array(key.Scopes),
		nullTime(key.ExpiresAt),
		nullTime(key.LastUsedAt),
		nullInet(key.LastUsedIP),
		key.UseCount,
		key.IsActive,
		nullTime(key.RevokedAt),
		nullString(key.RevokedReason),
		key.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create agent api key: %w", err)
	}
	return nil
}

// GetByID retrieves a key by ID.
func (r *AgentAPIKeyRepository) GetByID(ctx context.Context, id shared.ID) (*agentdom.APIKey, error) {
	query := "SELECT" + agentAPIKeyColumns + " FROM agent_api_keys WHERE id = $1"
	return r.scanOne(r.db.QueryRowContext(ctx, query, id.String()))
}

// GetByHash retrieves an ACTIVE key by hash. Revoked/inactive keys are excluded
// so the auth path never resurrects a killed credential. Expiry is enforced by
// the caller via APIKey.IsValid so an expired-but-active key still resolves (and
// is then rejected) rather than silently 404ing.
func (r *AgentAPIKeyRepository) GetByHash(ctx context.Context, hash string) (*agentdom.APIKey, error) {
	query := "SELECT" + agentAPIKeyColumns + " FROM agent_api_keys WHERE key_hash = $1 AND is_active = TRUE"
	return r.scanOne(r.db.QueryRowContext(ctx, query, hash))
}

// GetByAgentID retrieves all keys for an agent, newest first.
func (r *AgentAPIKeyRepository) GetByAgentID(ctx context.Context, agentID shared.ID) ([]*agentdom.APIKey, error) {
	query := "SELECT" + agentAPIKeyColumns + " FROM agent_api_keys WHERE agent_id = $1 " + orderByCreatedAtDesc
	rows, err := r.db.QueryContext(ctx, query, agentID.String())
	if err != nil {
		return nil, fmt.Errorf("get keys by agent: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return r.scanMany(rows)
}

// List lists keys with optional filters.
func (r *AgentAPIKeyRepository) List(ctx context.Context, filter agentdom.APIKeyFilter) ([]*agentdom.APIKey, error) {
	query := "SELECT" + agentAPIKeyColumns + " FROM agent_api_keys WHERE 1=1"
	args := []any{}
	i := 1
	if filter.AgentID != nil {
		query += fmt.Sprintf(" AND agent_id = $%d", i)
		args = append(args, filter.AgentID.String())
		i++
	}
	if filter.IsActive != nil {
		query += fmt.Sprintf(" AND is_active = $%d", i)
		args = append(args, *filter.IsActive)
		i++
	}
	query += " " + orderByCreatedAtDesc

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list agent api keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return r.scanMany(rows)
}

// Update updates a key's mutable fields.
func (r *AgentAPIKeyRepository) Update(ctx context.Context, key *agentdom.APIKey) error {
	query := `
		UPDATE agent_api_keys
		SET name = $2, scopes = $3, expires_at = $4, last_used_at = $5,
		    last_used_ip = $6, use_count = $7, is_active = $8,
		    revoked_at = $9, revoked_reason = $10
		WHERE id = $1`
	res, err := r.db.ExecContext(ctx, query,
		key.ID.String(),
		key.Name,
		pq.Array(key.Scopes),
		nullTime(key.ExpiresAt),
		nullTime(key.LastUsedAt),
		nullInet(key.LastUsedIP),
		key.UseCount,
		key.IsActive,
		nullTime(key.RevokedAt),
		nullString(key.RevokedReason),
	)
	if err != nil {
		return fmt.Errorf("update agent api key: %w", err)
	}
	return oneRowAffected(res, agentdom.ErrAgentNotFound)
}

// Delete removes a key.
func (r *AgentAPIKeyRepository) Delete(ctx context.Context, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, "DELETE FROM agent_api_keys WHERE id = $1", id.String())
	if err != nil {
		return fmt.Errorf("delete agent api key: %w", err)
	}
	return oneRowAffected(res, agentdom.ErrAgentNotFound)
}

// RecordUsage bumps use_count and last-used fields. Best-effort: a missing row
// is not an error (the key may have been revoked between auth and this async
// update).
func (r *AgentAPIKeyRepository) RecordUsage(ctx context.Context, id shared.ID, ip string) error {
	query := `
		UPDATE agent_api_keys
		SET use_count = use_count + 1, last_used_at = NOW(), last_used_ip = $2
		WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), nullInet(ip))
	if err != nil {
		return fmt.Errorf("record agent api key usage: %w", err)
	}
	return nil
}

// Revoke deactivates a key with a reason.
func (r *AgentAPIKeyRepository) Revoke(ctx context.Context, id shared.ID, reason string) error {
	query := `
		UPDATE agent_api_keys
		SET is_active = FALSE, revoked_at = NOW(), revoked_reason = $2
		WHERE id = $1 AND is_active = TRUE`
	res, err := r.db.ExecContext(ctx, query, id.String(), nullString(reason))
	if err != nil {
		return fmt.Errorf("revoke agent api key: %w", err)
	}
	return oneRowAffected(res, agentdom.ErrAgentNotFound)
}

// CountActiveByAgentID counts active keys for an agent.
func (r *AgentAPIKeyRepository) CountActiveByAgentID(ctx context.Context, agentID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM agent_api_keys WHERE agent_id = $1 AND is_active = TRUE",
		agentID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count active agent api keys: %w", err)
	}
	return n, nil
}

func (r *AgentAPIKeyRepository) scanOne(row *sql.Row) (*agentdom.APIKey, error) {
	k, err := r.scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, agentdom.ErrAgentNotFound
	}
	return k, err
}

func (r *AgentAPIKeyRepository) scanMany(rows *sql.Rows) ([]*agentdom.APIKey, error) {
	keys := make([]*agentdom.APIKey, 0)
	for rows.Next() {
		k, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (r *AgentAPIKeyRepository) scan(s rowScanner) (*agentdom.APIKey, error) {
	var (
		k          agentdom.APIKey
		id         string
		agentID    string
		scopes     pq.StringArray
		expiresAt  sql.NullTime
		lastUsedAt sql.NullTime
		lastUsedIP sql.NullString
		revokedAt  sql.NullTime
		revoked    sql.NullString
	)
	if err := s.Scan(
		&id, &agentID, &k.Name, &k.KeyHash, &k.KeyPrefix, &scopes,
		&expiresAt, &lastUsedAt, &lastUsedIP, &k.UseCount,
		&k.IsActive, &revokedAt, &revoked, &k.CreatedAt,
	); err != nil {
		return nil, err
	}
	k.ID, _ = shared.IDFromString(id)
	k.AgentID, _ = shared.IDFromString(agentID)
	k.Scopes = scopes
	k.ExpiresAt = nullTimeValue(expiresAt)
	k.LastUsedAt = nullTimeValue(lastUsedAt)
	k.LastUsedIP = nullStringValue(lastUsedIP)
	k.RevokedAt = nullTimeValue(revokedAt)
	k.RevokedReason = nullStringValue(revoked)
	return &k, nil
}

// nullInet maps an IP string to a NULL-able INET value; empty → NULL.
func nullInet(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}

// oneRowAffected maps a zero-row result to notFound.
func oneRowAffected(res sql.Result, notFound error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound
	}
	return nil
}

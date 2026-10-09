package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CreateClient implements mcpoauth.ClientRepository: a client an
// organization registered, or a dynamically registered one.
func (r *MCPOAuthRepository) CreateClient(ctx context.Context, c *mcpoauth.Client) (*mcpoauth.Client, error) {
	q := `INSERT INTO mcp_oauth_clients AS c (client_id, kind, tenant_id, name, redirect_uris)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING ` + mcpClientColumns
	out := &mcpoauth.Client{}
	if err := scanMCPClient(r.db.QueryRowContext(ctx, q, c.ClientID, string(c.Kind), nullableID(c.TenantID), c.Name,
		pq.Array(c.RedirectURIs)), out); err != nil {
		return nil, fmt.Errorf("create mcp client: %w", err)
	}
	return out, nil
}

// ListOrganizationClients implements mcpoauth.ClientRepository.
func (r *MCPOAuthRepository) ListOrganizationClients(ctx context.Context, tenantID shared.ID) ([]mcpoauth.Client, error) {
	q := `SELECT ` + mcpClientColumns + ` FROM mcp_oauth_clients c
		WHERE c.tenant_id = $1 AND c.kind = 'organization' ORDER BY c.created_at DESC LIMIT 200`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list organization mcp clients: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []mcpoauth.Client{}
	for rows.Next() {
		var c mcpoauth.Client
		if err := scanMCPClient(rows, &c); err != nil {
			return nil, fmt.Errorf("scan mcp client: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteOrganizationClient implements mcpoauth.ClientRepository. Its
// connections and pending requests go with it (cascade).
func (r *MCPOAuthRepository) DeleteOrganizationClient(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM mcp_oauth_clients WHERE id = $1 AND tenant_id = $2 AND kind = 'organization'`,
		id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("delete organization mcp client: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return mcpoauth.ErrNotFound
	}
	return nil
}

// PurgeForPlatform implements mcpoauth.ClientRepository: deletes what is past
// any use. Authorization requests a day after they ended (a code presented
// again later is then simply unknown), tokens once expired (a rotated
// refresh token is kept until then, so its reuse is still detected), grants
// 30 days after they were revoked or expired, dynamically registered clients
// unused for 30 days, and metadata-document clients with no connection that
// were not fetched for 90 days. Blocked clients are kept: the block must
// outlive the purge.
func (r *MCPOAuthRepository) PurgeForPlatform(ctx context.Context, now time.Time) (int64, error) {
	stmts := []struct {
		q   string
		arg time.Time
	}{
		{`DELETE FROM mcp_oauth_requests WHERE expires_at < $1`, now.Add(-24 * time.Hour)},
		{`DELETE FROM mcp_oauth_tokens WHERE expires_at < $1`, now},
		{`DELETE FROM mcp_oauth_grants WHERE COALESCE(revoked_at, expires_at) < $1`, now.Add(-30 * 24 * time.Hour)},
		{`DELETE FROM mcp_oauth_clients c WHERE c.kind = 'dynamic' AND c.blocked_at IS NULL AND c.created_at < $1
			AND NOT EXISTS (SELECT 1 FROM mcp_oauth_grants g WHERE g.client_ref = c.id)`, now.Add(-30 * 24 * time.Hour)},
		{`DELETE FROM mcp_oauth_clients c WHERE c.kind = 'metadata_document' AND c.blocked_at IS NULL AND c.updated_at < $1
			AND NOT EXISTS (SELECT 1 FROM mcp_oauth_grants g WHERE g.client_ref = c.id)`, now.Add(-90 * 24 * time.Hour)},
	}
	var total int64
	for _, s := range stmts {
		res, err := r.db.ExecContext(ctx, s.q, s.arg)
		if err != nil {
			return total, fmt.Errorf("purge mcp oauth state: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

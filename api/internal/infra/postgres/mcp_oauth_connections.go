package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxMCPConnections bounds a connections list (one organization).
const maxMCPConnections = 500

// ListConnections implements mcpoauth.ConnectionRepository: the active
// grants of an organization, of one user when userID is set, newest first.
func (r *MCPOAuthRepository) ListConnections(ctx context.Context, tenantID shared.ID, userID *shared.ID, now time.Time) ([]mcpoauth.Connection, error) {
	q := mcpGrantSelectCols + `, u.name, u.email
		FROM mcp_oauth_grants g
		JOIN mcp_oauth_clients c ON c.id = g.client_ref
		JOIN users u ON u.id = g.user_id
		WHERE g.tenant_id = $1 AND g.revoked_at IS NULL AND g.expires_at > $2 AND ($3::uuid IS NULL OR g.user_id = $3::uuid)
		ORDER BY g.created_at DESC
		LIMIT ` + fmt.Sprint(maxMCPConnections)
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), now, nullableID(userID))
	if err != nil {
		return nil, fmt.Errorf("list mcp connections: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []mcpoauth.Connection{}
	for rows.Next() {
		var c mcpoauth.Connection
		g, err := scanMCPGrantRow(rows, &c.UserName, &c.UserEmail)
		if err != nil {
			return nil, fmt.Errorf("scan mcp connection: %w", err)
		}
		c.Grant = *g
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetGrant implements mcpoauth.ConnectionRepository.
func (r *MCPOAuthRepository) GetGrant(ctx context.Context, tenantID, grantID shared.ID) (*mcpoauth.Grant, error) {
	q := mcpGrantSelectCols + `, '', ''
		FROM mcp_oauth_grants g
		JOIN mcp_oauth_clients c ON c.id = g.client_ref
		WHERE g.tenant_id = $1 AND g.id = $2`
	var name, email string
	g, err := scanMCPGrantRow(r.db.QueryRowContext(ctx, q, tenantID.String(), grantID.String()), &name, &email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mcpoauth.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mcp grant: %w", err)
	}
	return g, nil
}

// scanMCPGrantRow scans mcpGrantSelectCols followed by two text columns.
func scanMCPGrantRow(row rowScanner, extra1, extra2 *string) (*mcpoauth.Grant, error) {
	var (
		g                            mcpoauth.Grant
		id, tenantID, userID         string
		scopes                       []string
		lastUsed, revoked            sql.NullTime
		cid, ctenant                 sql.NullString
		ckind                        string
		cfetched, cexpires, cblocked sql.NullTime
	)
	if err := row.Scan(&id, &tenantID, &userID, &g.Resource, pq.Array(&scopes), &g.CreatedAt, &lastUsed,
		&g.LastUsedIP, &g.ExpiresAt, &revoked, &g.RevokedReason, &g.DPoPJKT,
		&cid, &g.Client.ClientID, &ckind, &ctenant, &g.Client.Name, pq.Array(&g.Client.RedirectURIs),
		&cfetched, &cexpires, &cblocked, &g.Client.CreatedAt, extra1, extra2); err != nil {
		return nil, err
	}
	g.ID = shared.MustIDFromString(id)
	g.TenantID = shared.MustIDFromString(tenantID)
	g.UserID = shared.MustIDFromString(userID)
	g.Scopes = toScopes(scopes)
	g.LastUsedAt = timePtr(lastUsed)
	g.RevokedAt = timePtr(revoked)
	g.Client.ID = shared.MustIDFromString(cid.String)
	g.Client.Kind = mcpoauth.ClientKind(ckind)
	g.Client.TenantID = idPtr(ctenant)
	g.Client.FetchedAt = timePtr(cfetched)
	g.Client.ExpiresAt = timePtr(cexpires)
	g.Client.BlockedAt = timePtr(cblocked)
	return &g, nil
}

// ListClientsForPlatform implements mcpoauth.ConnectionRepository: every
// client with how many active connections it has and in how many
// organizations. Counts only, no tenant data (platform admin console).
func (r *MCPOAuthRepository) ListClientsForPlatform(ctx context.Context, now time.Time) ([]mcpoauth.ClientUsage, error) {
	q := `SELECT ` + mcpClientColumns + `,
			COUNT(g.id) FILTER (WHERE g.revoked_at IS NULL AND g.expires_at > $1),
			COUNT(DISTINCT g.tenant_id) FILTER (WHERE g.revoked_at IS NULL AND g.expires_at > $1),
			MAX(g.last_used_at)
		FROM mcp_oauth_clients c
		LEFT JOIN mcp_oauth_grants g ON g.client_ref = c.id
		GROUP BY c.id
		ORDER BY c.created_at DESC
		LIMIT 1000`
	rows, err := r.db.QueryContext(ctx, q, now)
	if err != nil {
		return nil, fmt.Errorf("list mcp clients: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []mcpoauth.ClientUsage{}
	for rows.Next() {
		var (
			u                             mcpoauth.ClientUsage
			id, tenantID                  sql.NullString
			kind                          string
			fetched, expires, blocked, lu sql.NullTime
		)
		if err := rows.Scan(&id, &u.Client.ClientID, &kind, &tenantID, &u.Client.Name, pq.Array(&u.Client.RedirectURIs),
			&fetched, &expires, &blocked, &u.Client.CreatedAt, &u.ActiveConnections, &u.Organizations, &lu); err != nil {
			return nil, fmt.Errorf("scan mcp client: %w", err)
		}
		u.Client.ID = shared.MustIDFromString(id.String)
		u.Client.Kind = mcpoauth.ClientKind(kind)
		u.Client.TenantID = idPtr(tenantID)
		u.Client.FetchedAt = timePtr(fetched)
		u.Client.ExpiresAt = timePtr(expires)
		u.Client.BlockedAt = timePtr(blocked)
		u.LastUsedAt = timePtr(lu)
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetClientBlockedForPlatform implements mcpoauth.ConnectionRepository. A
// blocked client cannot authorize, and its existing tokens stop working.
func (r *MCPOAuthRepository) SetClientBlockedForPlatform(ctx context.Context, clientRef shared.ID, blocked bool, now time.Time) error {
	var at any
	if blocked {
		at = now
	}
	res, err := r.db.ExecContext(ctx, `UPDATE mcp_oauth_clients SET blocked_at = $2, updated_at = $3 WHERE id = $1`, clientRef.String(), at, now)
	if err != nil {
		return fmt.Errorf("block mcp client: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return mcpoauth.ErrNotFound
	}
	return nil
}

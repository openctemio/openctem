package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ mcpoauth.ConfirmationRepository = (*MCPOAuthRepository)(nil)

// CreateConfirmation implements mcpoauth.ConfirmationRepository.
func (r *MCPOAuthRepository) CreateConfirmation(ctx context.Context, c *mcpoauth.Confirmation) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO mcp_action_confirmations (id, tenant_id, grant_id, user_id, tool, args_digest, summary, status, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9)`,
		c.ID.String(), c.TenantID.String(), c.GrantID.String(), c.UserID.String(), c.Tool, c.ArgsDigest, c.Summary, c.CreatedAt, c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create mcp confirmation: %w", err)
	}
	return nil
}

// GetConfirmation implements mcpoauth.ConfirmationRepository.
func (r *MCPOAuthRepository) GetConfirmation(ctx context.Context, tenantID, userID, id shared.ID) (*mcpoauth.Confirmation, error) {
	var (
		c                      mcpoauth.Confirmation
		cid, tid, gid, uid, st string
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT a.id, a.tenant_id, a.grant_id, a.user_id, a.tool, a.args_digest, a.summary, a.status, a.created_at, a.expires_at, cl.name
		  FROM mcp_action_confirmations a
		  JOIN mcp_oauth_grants g ON g.id = a.grant_id
		  JOIN mcp_oauth_clients cl ON cl.id = g.client_ref
		 WHERE a.tenant_id = $1 AND a.user_id = $2 AND a.id = $3`, tenantID.String(), userID.String(), id.String()).
		Scan(&cid, &tid, &gid, &uid, &c.Tool, &c.ArgsDigest, &c.Summary, &st, &c.CreatedAt, &c.ExpiresAt, &c.ClientName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mcpoauth.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mcp confirmation: %w", err)
	}
	c.ID, c.TenantID, c.GrantID, c.UserID = shared.MustIDFromString(cid), shared.MustIDFromString(tid), shared.MustIDFromString(gid), shared.MustIDFromString(uid)
	c.Status = mcpoauth.ConfirmationStatus(st)
	return &c, nil
}

// DecideConfirmation implements mcpoauth.ConfirmationRepository.
func (r *MCPOAuthRepository) DecideConfirmation(ctx context.Context, tenantID, userID, id shared.ID, approve bool, now time.Time) error {
	status := mcpoauth.ConfirmationDenied
	if approve {
		status = mcpoauth.ConfirmationApproved
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE mcp_action_confirmations SET status = $4, decided_at = $5
		 WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND status = 'pending' AND expires_at > $5`,
		tenantID.String(), userID.String(), id.String(), string(status), now)
	if err != nil {
		return fmt.Errorf("decide mcp confirmation: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return mcpoauth.ErrNotFound
	}
	return nil
}

// UseConfirmation implements mcpoauth.ConfirmationRepository.
func (r *MCPOAuthRepository) UseConfirmation(ctx context.Context, tenantID, grantID, id shared.ID, tool, digest string, now time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE mcp_action_confirmations SET status = 'used'
		 WHERE tenant_id = $1 AND grant_id = $2 AND id = $3 AND tool = $4 AND args_digest = $5
		   AND status = 'approved' AND expires_at > $6`,
		tenantID.String(), grantID.String(), id.String(), tool, digest, now)
	if err != nil {
		return fmt.Errorf("use mcp confirmation: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return mcpoauth.ErrConfirmationRequired
	}
	return nil
}

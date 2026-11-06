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

// Access requests to approve an AI application publisher
// (docs/architecture/mcp-authorization.md, "Access requests"). Every query
// carries the tenant.

var _ mcpoauth.AccessRequestRepository = (*MCPOAuthRepository)(nil)

// maxPendingAccessRequestsListed bounds the pending list (the service caps
// pending requests per organization well below it).
const maxPendingAccessRequestsListed = 200

const mcpAccessRequestColumns = `a.id, a.tenant_id, a.client_host, a.client_name, a.client_id, a.scopes,
	a.requested_by, COALESCE(u.name, ''), a.request_count, a.status, a.decided_by, a.decided_at, a.created_at, a.updated_at`

const mcpAccessRequestFrom = ` FROM mcp_access_requests a LEFT JOIN users u ON u.id = a.requested_by`

// UpsertAccessRequest implements mcpoauth.AccessRequestRepository.
func (r *MCPOAuthRepository) UpsertAccessRequest(ctx context.Context, a *mcpoauth.AccessRequest) (bool, error) {
	var (
		id        string
		created   bool
		requester sql.NullString
	)
	if a.RequestedBy != nil {
		requester = sql.NullString{String: a.RequestedBy.String(), Valid: true}
	}
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO mcp_access_requests (id, tenant_id, client_host, client_name, client_id, scopes, requested_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
		ON CONFLICT (tenant_id, client_host) WHERE status = 'pending' DO UPDATE SET
			request_count = mcp_access_requests.request_count + 1,
			client_name = EXCLUDED.client_name,
			scopes = ARRAY(SELECT DISTINCT s FROM unnest(mcp_access_requests.scopes || EXCLUDED.scopes) AS s ORDER BY s),
			updated_at = EXCLUDED.updated_at
		RETURNING id, (xmax = 0)`,
		a.ID.String(), a.TenantID.String(), a.ClientHost, a.ClientName, a.ClientID, pq.Array(scopeStrings(a.Scopes)),
		requester, a.CreatedAt).Scan(&id, &created)
	if err != nil {
		return false, fmt.Errorf("upsert mcp access request: %w", err)
	}
	a.ID = shared.MustIDFromString(id)
	return created, nil
}

// CountAccessRequestsCreatedBy implements mcpoauth.AccessRequestRepository.
func (r *MCPOAuthRepository) CountAccessRequestsCreatedBy(ctx context.Context, tenantID, userID shared.ID, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM mcp_access_requests WHERE tenant_id = $1 AND requested_by = $2 AND created_at > $3`,
		tenantID.String(), userID.String(), since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count mcp access requests: %w", err)
	}
	return n, nil
}

// CountPendingAccessRequests implements mcpoauth.AccessRequestRepository.
func (r *MCPOAuthRepository) CountPendingAccessRequests(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM mcp_access_requests WHERE tenant_id = $1 AND status = 'pending'`,
		tenantID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count pending mcp access requests: %w", err)
	}
	return n, nil
}

// PendingAccessRequestForHost implements mcpoauth.AccessRequestRepository.
func (r *MCPOAuthRepository) PendingAccessRequestForHost(ctx context.Context, tenantID shared.ID, host string) (*mcpoauth.AccessRequest, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+mcpAccessRequestColumns+mcpAccessRequestFrom+`
		WHERE a.tenant_id = $1 AND a.client_host = $2 AND a.status = 'pending'`, tenantID.String(), host)
	return scanMCPAccessRequest(row)
}

// ListPendingAccessRequests implements mcpoauth.AccessRequestRepository.
func (r *MCPOAuthRepository) ListPendingAccessRequests(ctx context.Context, tenantID shared.ID) ([]mcpoauth.AccessRequest, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+mcpAccessRequestColumns+mcpAccessRequestFrom+`
		WHERE a.tenant_id = $1 AND a.status = 'pending' ORDER BY a.updated_at DESC LIMIT $2`,
		tenantID.String(), maxPendingAccessRequestsListed)
	if err != nil {
		return nil, fmt.Errorf("list mcp access requests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []mcpoauth.AccessRequest{}
	for rows.Next() {
		a, err := scanMCPAccessRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// GetAccessRequest implements mcpoauth.AccessRequestRepository.
func (r *MCPOAuthRepository) GetAccessRequest(ctx context.Context, tenantID, id shared.ID) (*mcpoauth.AccessRequest, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+mcpAccessRequestColumns+mcpAccessRequestFrom+`
		WHERE a.tenant_id = $1 AND a.id = $2`, tenantID.String(), id.String())
	return scanMCPAccessRequest(row)
}

// DecideAccessRequest implements mcpoauth.AccessRequestRepository.
func (r *MCPOAuthRepository) DecideAccessRequest(ctx context.Context, tenantID, id, decidedBy shared.ID, approve bool, now time.Time) error {
	status := mcpoauth.AccessRequestDenied
	if approve {
		status = mcpoauth.AccessRequestApproved
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE mcp_access_requests SET status = $4, decided_by = $5, decided_at = $6, updated_at = $6
		 WHERE tenant_id = $1 AND id = $2 AND status = $3`,
		tenantID.String(), id.String(), string(mcpoauth.AccessRequestPending), string(status), decidedBy.String(), now)
	if err != nil {
		return fmt.Errorf("decide mcp access request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return mcpoauth.ErrNotFound
	}
	return nil
}

// ActiveAdminIDs implements mcpoauth.AccessRequestRepository: the active
// owners and administrators of the tenant.
func (r *MCPOAuthRepository) ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT m.user_id
		  FROM tenant_members m
		  JOIN users u ON u.id = m.user_id AND u.status = 'active'
		  JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		 WHERE m.tenant_id = $1 AND m.status = 'active' AND ver.role IN ('owner', 'admin')`,
		tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list mcp admins: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan mcp admin: %w", err)
		}
		out = append(out, shared.MustIDFromString(id))
	}
	return out, rows.Err()
}

func scanMCPAccessRequest(s interface{ Scan(dest ...any) error }) (*mcpoauth.AccessRequest, error) {
	var (
		a                    mcpoauth.AccessRequest
		id, tid, status      string
		scopes               []string
		requestedBy, decided sql.NullString
		decidedAt            sql.NullTime
	)
	err := s.Scan(&id, &tid, &a.ClientHost, &a.ClientName, &a.ClientID, pq.Array(&scopes),
		&requestedBy, &a.RequesterName, &a.RequestCount, &status, &decided, &decidedAt, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mcpoauth.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan mcp access request: %w", err)
	}
	a.ID, a.TenantID, a.Status = shared.MustIDFromString(id), shared.MustIDFromString(tid), mcpoauth.AccessRequestStatus(status)
	for _, sc := range scopes {
		a.Scopes = append(a.Scopes, mcpoauth.Scope(sc))
	}
	if requestedBy.Valid {
		u := shared.MustIDFromString(requestedBy.String)
		a.RequestedBy = &u
	}
	if decided.Valid {
		u := shared.MustIDFromString(decided.String)
		a.DecidedBy = &u
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		a.DecidedAt = &t
	}
	return &a, nil
}

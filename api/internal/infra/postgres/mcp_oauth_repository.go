package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MCPOAuthRepository persists the OAuth state of the MCP endpoint
// (RFC-062): clients, authorization requests, grants and tokens. Codes and
// tokens arrive already hashed.
type MCPOAuthRepository struct {
	db *DB
}

// NewMCPOAuthRepository creates the repository.
func NewMCPOAuthRepository(db *DB) *MCPOAuthRepository {
	return &MCPOAuthRepository{db: db}
}

var _ mcpoauth.Repository = (*MCPOAuthRepository)(nil)

const mcpClientColumns = `c.id, c.client_id, c.kind, c.tenant_id, c.name, c.redirect_uris,
	c.metadata_fetched_at, c.metadata_expires_at, c.blocked_at, c.created_at`

func scanMCPClient(row rowScanner, c *mcpoauth.Client) error {
	var (
		id, tenantID sql.NullString
		kind         string
		fetched      sql.NullTime
		expires      sql.NullTime
		blocked      sql.NullTime
	)
	if err := row.Scan(&id, &c.ClientID, &kind, &tenantID, &c.Name, pq.Array(&c.RedirectURIs),
		&fetched, &expires, &blocked, &c.CreatedAt); err != nil {
		return err
	}
	c.ID = shared.MustIDFromString(id.String)
	c.Kind = mcpoauth.ClientKind(kind)
	c.TenantID = idPtr(tenantID)
	c.FetchedAt = timePtr(fetched)
	c.ExpiresAt = timePtr(expires)
	c.BlockedAt = timePtr(blocked)
	return nil
}

// UpsertClient implements mcpoauth.Repository.
func (r *MCPOAuthRepository) UpsertClient(ctx context.Context, c *mcpoauth.Client) (*mcpoauth.Client, error) {
	const q = `
		INSERT INTO mcp_oauth_clients AS c (client_id, kind, tenant_id, name, redirect_uris, metadata_fetched_at, metadata_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (client_id) DO UPDATE SET
			name = EXCLUDED.name,
			redirect_uris = EXCLUDED.redirect_uris,
			metadata_fetched_at = EXCLUDED.metadata_fetched_at,
			metadata_expires_at = EXCLUDED.metadata_expires_at,
			updated_at = now()
		WHERE c.kind = EXCLUDED.kind
		RETURNING ` + mcpClientColumns
	out := &mcpoauth.Client{}
	err := scanMCPClient(r.db.QueryRowContext(ctx, q, c.ClientID, string(c.Kind), nullableID(c.TenantID), c.Name,
		pq.Array(c.RedirectURIs), c.FetchedAt, c.ExpiresAt), out)
	if errors.Is(err, sql.ErrNoRows) {
		// The client_id exists with another kind: never let one kind of
		// registration overwrite another.
		return nil, fmt.Errorf("%w: client_id already registered differently", shared.ErrConflict)
	}
	if err != nil {
		return nil, fmt.Errorf("upsert mcp client: %w", err)
	}
	return out, nil
}

// GetClientByClientID implements mcpoauth.Repository.
func (r *MCPOAuthRepository) GetClientByClientID(ctx context.Context, clientID string) (*mcpoauth.Client, error) {
	q := `SELECT ` + mcpClientColumns + ` FROM mcp_oauth_clients c WHERE c.client_id = $1`
	out := &mcpoauth.Client{}
	if err := scanMCPClient(r.db.QueryRowContext(ctx, q, clientID), out); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, mcpoauth.ErrNotFound
		}
		return nil, fmt.Errorf("get mcp client: %w", err)
	}
	return out, nil
}

// pendingClient is the snapshot of a metadata document kept on an
// authorization request until a person approves it.
type pendingClient struct {
	ClientID     string     `json:"client_id"`
	Name         string     `json:"name"`
	RedirectURIs []string   `json:"redirect_uris"`
	FetchedAt    *time.Time `json:"fetched_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// CreateRequest implements mcpoauth.Repository. A pending client is not
// stored in mcp_oauth_clients: its document travels with the request.
func (r *MCPOAuthRepository) CreateRequest(ctx context.Context, req *mcpoauth.AuthRequest) error {
	const q = `
		INSERT INTO mcp_oauth_requests (id, client_ref, pending_client, redirect_uri, state, code_challenge, resource, scopes, status, created_at, expires_at,
			flow, device_code_hash, user_code_hash, poll_interval_seconds, requester_ip, requester_ua)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11, NULLIF($12, ''), NULLIF($13, ''), $14, $15, $16)`
	var ref, snap any
	if req.Client.ID != (shared.ID{}) {
		ref = req.Client.ID.String()
	}
	if req.ClientPending {
		b, err := json.Marshal(pendingClient{
			ClientID: req.Client.ClientID, Name: req.Client.Name, RedirectURIs: req.Client.RedirectURIs,
			FetchedAt: req.Client.FetchedAt, ExpiresAt: req.Client.ExpiresAt,
		})
		if err != nil {
			return fmt.Errorf("encode pending mcp client: %w", err)
		}
		snap = string(b)
	}
	interval := int(req.PollInterval / time.Second)
	if interval <= 0 {
		interval = int(mcpoauth.DevicePollInterval / time.Second)
	}
	_, err := r.db.ExecContext(ctx, q, req.ID.String(), ref, snap, req.RedirectURI, req.State,
		req.CodeChallenge, req.Resource, pq.Array(scopeStrings(req.Scopes)), req.CreatedAt, req.ExpiresAt,
		flowOrCode(req.Flow), req.DeviceCodeHash, req.UserCodeHash, interval,
		truncate(req.RequesterIP, 45), truncate(req.RequesterUserAgent, 256))
	if err != nil {
		return fmt.Errorf("create mcp authorization request: %w", err)
	}
	return nil
}

const mcpRequestSelect = `SELECT r.id, r.redirect_uri, r.state, r.code_challenge, r.resource, r.scopes, r.status,
	r.user_id, r.tenant_id, r.granted_scopes, r.code_expires_at, r.grant_id, r.full_data, r.created_at, r.expires_at, r.pending_client,
	r.flow, r.poll_interval_seconds, r.requester_ip, r.requester_ua,
	c.id, c.client_id, c.kind, c.tenant_id, c.name, c.redirect_uris,
	c.metadata_fetched_at, c.metadata_expires_at, c.blocked_at, c.created_at
	FROM mcp_oauth_requests r LEFT JOIN mcp_oauth_clients c ON c.id = r.client_ref`

func scanMCPRequest(row rowScanner) (*mcpoauth.AuthRequest, error) {
	var (
		req                          mcpoauth.AuthRequest
		id                           string
		status                       string
		scopes, granted              []string
		userID, tenantID, grantID    sql.NullString
		codeExpires                  sql.NullTime
		pending                      []byte
		cid, ctenant, cclient, cname sql.NullString
		ckind                        sql.NullString
		curis                        []string
		cfetched, cexpires, cblocked sql.NullTime
		ccreated                     sql.NullTime
		flow                         string
		interval                     int
	)
	err := row.Scan(&id, &req.RedirectURI, &req.State, &req.CodeChallenge, &req.Resource, pq.Array(&scopes), &status,
		&userID, &tenantID, pq.Array(&granted), &codeExpires, &grantID, &req.FullData, &req.CreatedAt, &req.ExpiresAt, &pending,
		&flow, &interval, &req.RequesterIP, &req.RequesterUserAgent,
		&cid, &cclient, &ckind, &ctenant, &cname, pq.Array(&curis),
		&cfetched, &cexpires, &cblocked, &ccreated)
	if err != nil {
		return nil, err
	}
	req.ID = shared.MustIDFromString(id)
	req.Flow = mcpoauth.Flow(flow)
	req.PollInterval = time.Duration(interval) * time.Second
	req.Status = mcpoauth.RequestStatus(status)
	req.Scopes = toScopes(scopes)
	req.GrantedScopes = toScopes(granted)
	req.UserID = idPtr(userID)
	req.TenantID = idPtr(tenantID)
	req.GrantID = idPtr(grantID)
	req.CodeExpiresAt = timePtr(codeExpires)
	if cid.Valid {
		req.Client.ID = shared.MustIDFromString(cid.String)
		req.Client.ClientID = cclient.String
		req.Client.Name = cname.String
		req.Client.RedirectURIs = curis
		req.Client.Kind = mcpoauth.ClientKind(ckind.String)
		req.Client.TenantID = idPtr(ctenant)
		req.Client.FetchedAt = timePtr(cfetched)
		req.Client.ExpiresAt = timePtr(cexpires)
		req.Client.BlockedAt = timePtr(cblocked)
		req.Client.CreatedAt = ccreated.Time
	}
	if len(pending) > 0 {
		// The document fetched for this request is what the redirect URI was
		// checked against; it overlays any older stored copy.
		var p pendingClient
		if err := json.Unmarshal(pending, &p); err != nil {
			return nil, fmt.Errorf("decode pending mcp client: %w", err)
		}
		req.ClientPending = true
		req.Client.ClientID = p.ClientID
		req.Client.Name = p.Name
		req.Client.RedirectURIs = p.RedirectURIs
		req.Client.Kind = mcpoauth.ClientKindMetadataDocument
		req.Client.FetchedAt = p.FetchedAt
		req.Client.ExpiresAt = p.ExpiresAt
	}
	return &req, nil
}

// GetRequest implements mcpoauth.Repository.
func (r *MCPOAuthRepository) GetRequest(ctx context.Context, id shared.ID) (*mcpoauth.AuthRequest, error) {
	req, err := scanMCPRequest(r.db.QueryRowContext(ctx, mcpRequestSelect+` WHERE r.id = $1`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mcpoauth.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mcp authorization request: %w", err)
	}
	return req, nil
}

// ClaimRequest implements mcpoauth.Repository.
func (r *MCPOAuthRepository) ClaimRequest(ctx context.Context, id, userID shared.ID, now time.Time) (*mcpoauth.AuthRequest, error) {
	const q = `
		UPDATE mcp_oauth_requests SET user_id = $2
		 WHERE id = $1 AND status = 'pending' AND expires_at > $3
		   AND (user_id = $2 OR (user_id IS NULL AND flow = 'code'))`
	res, err := r.db.ExecContext(ctx, q, id.String(), userID.String(), now)
	if err != nil {
		return nil, fmt.Errorf("claim mcp authorization request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, gerr := r.GetRequest(ctx, id); gerr != nil {
			return nil, gerr
		}
		return nil, mcpoauth.ErrRequestState
	}
	return r.GetRequest(ctx, id)
}

// ApproveRequest implements mcpoauth.Repository.
func (r *MCPOAuthRepository) ApproveRequest(ctx context.Context, id, userID, tenantID, clientRef shared.ID, granted []mcpoauth.Scope, fullData bool, codeHash string, codeExpiresAt, now time.Time) error {
	const q = `
		UPDATE mcp_oauth_requests
		   SET status = 'approved', tenant_id = $3, granted_scopes = $4, code_hash = NULLIF($5, ''),
		       code_expires_at = CASE WHEN $5 = '' THEN NULL ELSE $6::timestamptz END,
		       client_ref = $8, pending_client = NULL, full_data = $9
		 WHERE id = $1 AND user_id = $2 AND status = 'pending' AND expires_at > $7`
	res, err := r.db.ExecContext(ctx, q, id.String(), userID.String(), tenantID.String(),
		pq.Array(scopeStrings(granted)), codeHash, codeExpiresAt, now, clientRef.String(), fullData)
	if err != nil {
		return fmt.Errorf("approve mcp authorization request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return mcpoauth.ErrRequestState
	}
	return nil
}

// DenyRequest implements mcpoauth.Repository.
func (r *MCPOAuthRepository) DenyRequest(ctx context.Context, id, userID shared.ID, now time.Time) error {
	const q = `
		UPDATE mcp_oauth_requests SET status = 'denied'
		 WHERE id = $1 AND user_id = $2 AND status = 'pending' AND expires_at > $3`
	res, err := r.db.ExecContext(ctx, q, id.String(), userID.String(), now)
	if err != nil {
		return fmt.Errorf("deny mcp authorization request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return mcpoauth.ErrRequestState
	}
	return nil
}

// RedeemCode implements mcpoauth.Repository.
func (r *MCPOAuthRepository) RedeemCode(ctx context.Context, codeHash string, now time.Time) (*mcpoauth.AuthRequest, error) {
	const q = `
		UPDATE mcp_oauth_requests SET status = 'redeemed'
		 WHERE code_hash = $1 AND status = 'approved' AND code_expires_at > $2
		RETURNING id`
	var id string
	err := r.db.QueryRowContext(ctx, q, codeHash, now).Scan(&id)
	if err == nil {
		return r.GetRequest(ctx, shared.MustIDFromString(id))
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("redeem mcp authorization code: %w", err)
	}
	// Not redeemable: a second presentation of a redeemed code is reported
	// as such (the caller revokes what the first one created); an expired or
	// unknown code is simply not found.
	req, gerr := scanMCPRequest(r.db.QueryRowContext(ctx, mcpRequestSelect+` WHERE r.code_hash = $1`, codeHash))
	if errors.Is(gerr, sql.ErrNoRows) {
		return nil, mcpoauth.ErrNotFound
	}
	if gerr != nil {
		return nil, fmt.Errorf("read mcp authorization code: %w", gerr)
	}
	if req.Status == mcpoauth.RequestRedeemed {
		return req, mcpoauth.ErrCodeReused
	}
	return nil, mcpoauth.ErrNotFound
}

// CreateGrant implements mcpoauth.Repository.
func (r *MCPOAuthRepository) CreateGrant(ctx context.Context, g *mcpoauth.Grant, requestID shared.ID, tokens ...mcpoauth.Token) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		const qg = `
			INSERT INTO mcp_oauth_grants (id, tenant_id, user_id, client_ref, resource, scopes, created_at, expires_at, dpop_jkt, full_data, flow)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11)`
		if _, err := tx.ExecContext(ctx, qg, g.ID.String(), g.TenantID.String(), g.UserID.String(), g.Client.ID.String(),
			g.Resource, pq.Array(scopeStrings(g.Scopes)), g.CreatedAt, g.ExpiresAt, g.DPoPJKT, g.FullData, flowOrCode(g.Flow)); err != nil {
			return fmt.Errorf("insert mcp grant: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_requests SET grant_id = $2 WHERE id = $1 AND tenant_id = $3`,
			requestID.String(), g.ID.String(), g.TenantID.String()); err != nil {
			return fmt.Errorf("link mcp grant: %w", err)
		}
		return insertMCPTokens(ctx, tx, g.CreatedAt, tokens)
	})
}

func insertMCPTokens(ctx context.Context, tx *sql.Tx, now time.Time, tokens []mcpoauth.Token) error {
	const q = `INSERT INTO mcp_oauth_tokens (token_hash, grant_id, kind, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)`
	for _, t := range tokens {
		if _, err := tx.ExecContext(ctx, q, t.Hash, t.GrantID.String(), string(t.Kind), now, t.ExpiresAt); err != nil {
			return fmt.Errorf("insert mcp token: %w", err)
		}
	}
	return nil
}

// GetGrantByToken implements mcpoauth.Repository.
func (r *MCPOAuthRepository) GetGrantByToken(ctx context.Context, tokenHash string, kind mcpoauth.TokenKind, now time.Time) (*mcpoauth.Grant, error) {
	q := mcpGrantSelectCols + `, t.used_at
		FROM mcp_oauth_tokens t
		JOIN mcp_oauth_grants g ON g.id = t.grant_id
		JOIN mcp_oauth_clients c ON c.id = g.client_ref
		WHERE t.token_hash = $1 AND t.kind = $2 AND t.expires_at > $3`
	g, used, err := scanMCPGrantWithUse(r.db.QueryRowContext(ctx, q, tokenHash, string(kind), now))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mcpoauth.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mcp grant by token: %w", err)
	}
	if used {
		return g, mcpoauth.ErrRefreshReused
	}
	return g, nil
}

const mcpGrantSelectCols = `SELECT g.id, g.tenant_id, g.user_id, g.resource, g.scopes, g.created_at, g.last_used_at,
	COALESCE(g.last_used_ip, ''), g.expires_at, g.revoked_at, COALESCE(g.revoked_reason, ''), COALESCE(g.dpop_jkt, ''), g.full_data, g.flow, ` + mcpClientColumns

func scanMCPGrantWithUse(row rowScanner) (*mcpoauth.Grant, bool, error) {
	var (
		g                            mcpoauth.Grant
		id, tenantID, userID         string
		scopes                       []string
		lastUsed, revoked, used      sql.NullTime
		cid, ctenant                 sql.NullString
		ckind, flow                  string
		cfetched, cexpires, cblocked sql.NullTime
	)
	if err := row.Scan(&id, &tenantID, &userID, &g.Resource, pq.Array(&scopes), &g.CreatedAt, &lastUsed,
		&g.LastUsedIP, &g.ExpiresAt, &revoked, &g.RevokedReason, &g.DPoPJKT, &g.FullData, &flow,
		&cid, &g.Client.ClientID, &ckind, &ctenant, &g.Client.Name, pq.Array(&g.Client.RedirectURIs),
		&cfetched, &cexpires, &cblocked, &g.Client.CreatedAt, &used); err != nil {
		return nil, false, err
	}
	g.ID = shared.MustIDFromString(id)
	g.Flow = mcpoauth.Flow(flow)
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
	return &g, used.Valid, nil
}

// RotateRefresh implements mcpoauth.Repository.
func (r *MCPOAuthRepository) RotateRefresh(ctx context.Context, tenantID shared.ID, oldHash string, scopes []mcpoauth.Scope, now time.Time, tokens ...mcpoauth.Token) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var grantID string
		err := tx.QueryRowContext(ctx, `
			UPDATE mcp_oauth_tokens SET used_at = $2
			 WHERE token_hash = $1 AND kind = 'refresh' AND used_at IS NULL AND expires_at > $2
			RETURNING grant_id`, oldHash, now).Scan(&grantID)
		if errors.Is(err, sql.ErrNoRows) {
			return mcpoauth.ErrRefreshReused
		}
		if err != nil {
			return fmt.Errorf("rotate mcp refresh token: %w", err)
		}
		if scopes != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_grants SET scopes = $2 WHERE id = $1 AND tenant_id = $3`,
				grantID, pq.Array(scopeStrings(scopes)), tenantID.String()); err != nil {
				return fmt.Errorf("narrow mcp grant: %w", err)
			}
		}
		return insertMCPTokens(ctx, tx, now, tokens)
	})
}

// RevokeGrant implements mcpoauth.Repository.
func (r *MCPOAuthRepository) RevokeGrant(ctx context.Context, tenantID, grantID shared.ID, reason string, now time.Time) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE mcp_oauth_grants SET revoked_at = $2, revoked_reason = $3
			 WHERE id = $1 AND tenant_id = $4 AND revoked_at IS NULL`, grantID.String(), now, reason, tenantID.String()); err != nil {
			return fmt.Errorf("revoke mcp grant: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM mcp_oauth_tokens t USING mcp_oauth_grants g
			 WHERE t.grant_id = g.id AND g.id = $1 AND g.tenant_id = $2`, grantID.String(), tenantID.String()); err != nil {
			return fmt.Errorf("delete mcp grant tokens: %w", err)
		}
		return nil
	})
}

// RevokeGrantsByUser implements mcpoauth.Repository. The user id is the only
// filter: the revocation is deliberately tenant-agnostic for that one user.
func (r *MCPOAuthRepository) RevokeGrantsByUser(ctx context.Context, userID shared.ID, reason string, now time.Time) (int, error) {
	var n int
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE mcp_oauth_grants SET revoked_at = $2, revoked_reason = $3
			 WHERE user_id = $1 AND revoked_at IS NULL`, userID.String(), now, reason)
		if err != nil {
			return fmt.Errorf("revoke user mcp grants: %w", err)
		}
		cnt, _ := res.RowsAffected()
		n = int(cnt)
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM mcp_oauth_tokens t USING mcp_oauth_grants g
			 WHERE t.grant_id = g.id AND g.user_id = $1`, userID.String()); err != nil {
			return fmt.Errorf("delete user mcp grant tokens: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE mcp_oauth_requests SET status = 'denied'
			 WHERE user_id = $1 AND status IN ('pending', 'approved')`, userID.String()); err != nil {
			return fmt.Errorf("cancel user mcp requests: %w", err)
		}
		return nil
	})
	return n, err
}

// SetGrantScoped implements mcpoauth.Repository. Tokens stay: they carry no
// data scope of their own, the next request resolves it from the grant.
func (r *MCPOAuthRepository) SetGrantScoped(ctx context.Context, tenantID, grantID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE mcp_oauth_grants SET full_data = false
		 WHERE id = $1 AND tenant_id = $2 AND full_data AND revoked_at IS NULL`, grantID.String(), tenantID.String())
	if err != nil {
		return false, fmt.Errorf("scope mcp grant: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// TouchGrant implements mcpoauth.Repository. At most one write a minute per
// grant: last use is shown to people, not used for decisions.
func (r *MCPOAuthRepository) TouchGrant(ctx context.Context, tenantID, grantID shared.ID, ip string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE mcp_oauth_grants SET last_used_at = $2, last_used_ip = NULLIF($3, '')
		 WHERE id = $1 AND tenant_id = $5 AND (last_used_at IS NULL OR last_used_at < $4)`,
		grantID.String(), now, truncate(ip, 45), now.Add(-time.Minute), tenantID.String())
	if err != nil {
		return fmt.Errorf("touch mcp grant: %w", err)
	}
	return nil
}

func scopeStrings(scopes []mcpoauth.Scope) []string {
	out := make([]string, len(scopes))
	for i, s := range scopes {
		out[i] = string(s)
	}
	return out
}

func toScopes(in []string) []mcpoauth.Scope {
	out := make([]mcpoauth.Scope, len(in))
	for i, s := range in {
		out[i] = mcpoauth.Scope(s)
	}
	return out
}

func idPtr(s sql.NullString) *shared.ID {
	if !s.Valid || s.String == "" {
		return nil
	}
	id, err := shared.IDFromString(s.String)
	if err != nil {
		return nil
	}
	return &id
}

func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

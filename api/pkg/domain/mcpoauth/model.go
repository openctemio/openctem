package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Lifetimes (RFC-062 §9).
const (
	// RequestTTL bounds an authorization transaction from /oauth/authorize
	// to the person's decision on the consent page.
	RequestTTL = 10 * time.Minute
	// CodeTTL is the life of an authorization code.
	CodeTTL = 60 * time.Second
	// AccessTokenTTL is the life of an access token.
	AccessTokenTTL = 10 * time.Minute
	// RefreshIdleTTL is how long an unused refresh token stays valid.
	RefreshIdleTTL = 14 * 24 * time.Hour
	// GrantMaxTTL is the absolute life of a grant; refresh tokens never
	// outlive it.
	GrantMaxTTL = 90 * 24 * time.Hour
)

// Token prefixes. The prefix tells the MCP endpoint which authenticator a
// bearer token belongs to; the rest is 256 bits of randomness.
const (
	AccessTokenPrefix  = "octm_at_"
	RefreshTokenPrefix = "octm_rt_"
)

// ClientKind is how a client identifies itself (RFC-062 §5).
type ClientKind string

const (
	// ClientKindMetadataDocument: the client_id is the https URL of a Client
	// ID Metadata Document.
	ClientKindMetadataDocument ClientKind = "metadata_document"
	// ClientKindOrganization: registered by an organization administrator.
	ClientKindOrganization ClientKind = "organization"
	// ClientKindDynamic: registered through dynamic client registration.
	ClientKindDynamic ClientKind = "dynamic"
)

// Client is an MCP client known to the authorization server. Every client is
// a public client: it authenticates by PKCE, never by a secret.
type Client struct {
	ID           shared.ID
	ClientID     string
	Kind         ClientKind
	TenantID     *shared.ID
	Name         string
	RedirectURIs []string
	FetchedAt    *time.Time
	ExpiresAt    *time.Time
	BlockedAt    *time.Time
	CreatedAt    time.Time
}

// RequestStatus is the state of an authorization transaction.
type RequestStatus string

const (
	RequestPending  RequestStatus = "pending"
	RequestApproved RequestStatus = "approved"
	RequestDenied   RequestStatus = "denied"
	RequestRedeemed RequestStatus = "redeemed"
)

// AuthRequest is one authorization transaction.
type AuthRequest struct {
	ID            shared.ID
	Client        Client
	RedirectURI   string
	State         string
	CodeChallenge string
	Resource      string
	Scopes        []Scope
	Status        RequestStatus
	UserID        *shared.ID
	TenantID      *shared.ID
	GrantedScopes []Scope
	CodeExpiresAt *time.Time
	GrantID       *shared.ID
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// Grant is what one person allowed one client to do in one organization.
type Grant struct {
	ID            shared.ID
	TenantID      shared.ID
	UserID        shared.ID
	Client        Client
	Resource      string
	Scopes        []Scope
	CreatedAt     time.Time
	LastUsedAt    *time.Time
	LastUsedIP    string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedReason string
}

// Active reports whether the grant can still be used at now.
func (g *Grant) Active(now time.Time) bool {
	return g.RevokedAt == nil && now.Before(g.ExpiresAt) && g.Client.BlockedAt == nil
}

// TokenKind distinguishes access from refresh tokens.
type TokenKind string

const (
	TokenAccess  TokenKind = "access"
	TokenRefresh TokenKind = "refresh"
)

// Token is a stored token: its hash, never its value.
type Token struct {
	Hash      string
	GrantID   shared.ID
	Kind      TokenKind
	ExpiresAt time.Time
}

// Revocation reasons recorded on a grant.
const (
	RevokedByClient       = "client"
	RevokedByUser         = "user"
	RevokedByAdmin        = "admin"
	RevokedRefreshReuse   = "refresh_reuse"
	RevokedCodeReuse      = "code_reuse"
	RevokedMembershipGone = "membership"
)

// Errors of the repository and the service.
var (
	ErrNotFound      = fmt.Errorf("%w: not found", shared.ErrNotFound)
	ErrRequestState  = errors.New("authorization request is not in the expected state")
	ErrCodeReused    = errors.New("authorization code already redeemed")
	ErrRefreshReused = errors.New("refresh token already rotated")
)

// Repository persists clients, authorization requests, grants and tokens.
// Every token and code argument is a hash.
type Repository interface {
	// UpsertClient creates the client or, when client_id exists, refreshes
	// its name, redirect URIs and metadata times. It returns the stored row.
	UpsertClient(ctx context.Context, c *Client) (*Client, error)
	GetClientByClientID(ctx context.Context, clientID string) (*Client, error)

	CreateRequest(ctx context.Context, r *AuthRequest) error
	// Authorization requests exist before any organization is chosen: they
	// are found by a random id and bound to the user who claims them.
	GetRequest(ctx context.Context, id shared.ID) (*AuthRequest, error)
	// ClaimRequest binds a pending, unexpired request to userID; a request
	// already claimed by someone else is ErrRequestState.
	ClaimRequest(ctx context.Context, id, userID shared.ID, now time.Time) (*AuthRequest, error)
	// ApproveRequest moves a pending request claimed by userID to approved
	// and stores the code hash.
	ApproveRequest(ctx context.Context, id, userID, tenantID shared.ID, granted []Scope, codeHash string, codeExpiresAt, now time.Time) error
	// DenyRequest moves a pending request claimed by userID to denied.
	DenyRequest(ctx context.Context, id, userID shared.ID, now time.Time) error
	// RedeemCode atomically moves the approved request holding codeHash to
	// redeemed and returns it. A request already redeemed is returned with
	// ErrCodeReused; no request is ErrNotFound.
	RedeemCode(ctx context.Context, codeHash string, now time.Time) (*AuthRequest, error)
	// CreateGrant stores the grant, its first tokens and links the request.
	CreateGrant(ctx context.Context, g *Grant, requestID shared.ID, tokens ...Token) error

	// GetGrantByToken returns the grant of an unexpired token of kind, with
	// its client. A refresh token already rotated is returned with
	// ErrRefreshReused.
	GetGrantByToken(ctx context.Context, tokenHash string, kind TokenKind, now time.Time) (*Grant, error)
	// RotateRefresh marks the refresh token used and stores the new tokens,
	// in one transaction; the token must be unused (else ErrRefreshReused).
	// scopes, when non-nil, narrows the grant.
	RotateRefresh(ctx context.Context, tenantID shared.ID, oldHash string, scopes []Scope, now time.Time, tokens ...Token) error
	// RevokeGrant revokes the grant and deletes its tokens.
	RevokeGrant(ctx context.Context, tenantID, grantID shared.ID, reason string, now time.Time) error
	// TouchGrant records the last use of a grant.
	TouchGrant(ctx context.Context, tenantID, grantID shared.ID, ip string, now time.Time) error
}

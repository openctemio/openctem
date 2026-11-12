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

	// A grant that may read all organization data (Grant.FullData) lives
	// shorter than a scoped one: a leaked token is worth more, so every
	// window is smaller.
	FullDataAccessTokenTTL = 5 * time.Minute
	FullDataRefreshIdleTTL = 24 * time.Hour
	FullDataGrantMaxTTL    = 7 * 24 * time.Hour
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

// Flow is how an authorization request reaches its person: the browser
// redirect of the authorization code grant, or a user code typed in by the
// person (the device authorization grant, RFC 8628).
type Flow string

const (
	FlowCode   Flow = "code"
	FlowDevice Flow = "device"
)

// AuthRequest is one authorization transaction.
type AuthRequest struct {
	ID     shared.ID
	Flow   Flow
	Client Client
	// ClientPending: Client is a metadata document fetched for this request
	// and not stored yet. It is stored when a signed-in person approves.
	ClientPending bool
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
	// FullData: the person chose, at consent, to let the connection read
	// all organization data (needs a full-data role and a fresh step-up).
	FullData bool
	// Device flow only: the hashes of the device code (polled by the client)
	// and of the user code (typed by the person), the polling interval, and
	// the address and user agent the request came from.
	DeviceCodeHash     string
	UserCodeHash       string
	PollInterval       time.Duration
	RequesterIP        string
	RequesterUserAgent string
	CreatedAt          time.Time
	ExpiresAt          time.Time
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
	// DPoPJKT is the thumbprint of the client key the grant is bound to
	// (RFC 9449), or "" for a bearer grant.
	DPoPJKT string
	// FullData: the connection may read all organization data while its
	// user still holds a full-data role (re-checked on every request).
	FullData bool
	// Flow is how the grant was obtained (FlowCode or FlowDevice).
	Flow Flow
}

// AccessTTL is the life of an access token of the grant: shorter when the
// grant may read all organization data.
func (g *Grant) AccessTTL() time.Duration {
	if g.FullData {
		return FullDataAccessTokenTTL
	}
	return AccessTokenTTL
}

// RefreshIdleTTL is how long an unused refresh token of the grant stays valid.
func (g *Grant) RefreshIdleTTL() time.Duration {
	if g.FullData {
		return FullDataRefreshIdleTTL
	}
	return RefreshIdleTTL
}

// MaxLifetime is the longest a new grant may last.
func MaxLifetime(fullData bool) time.Duration {
	if fullData {
		return FullDataGrantMaxTTL
	}
	return GrantMaxTTL
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
	RevokedByPolicy       = "policy"
	RevokedCredentials    = "credentials"
)

// Errors of the repository and the service.
var (
	ErrNotFound      = fmt.Errorf("%w: not found", shared.ErrNotFound)
	ErrRequestState  = errors.New("authorization request is not in the expected state")
	ErrCodeReused    = errors.New("authorization code already redeemed")
	ErrRefreshReused = errors.New("refresh token already rotated")
)

// DevicePoll is what a poll of a device code found (RFC 8628 §3.5).
type DevicePoll string

const (
	// DevicePending: nobody approved or refused yet.
	DevicePending DevicePoll = "pending"
	// DeviceSlowDown: polled before the interval passed; the interval grew.
	DeviceSlowDown DevicePoll = "slow_down"
	// DeviceDenied: the person refused.
	DeviceDenied DevicePoll = "denied"
	// DeviceExpired: the request ended before it was approved and redeemed.
	DeviceExpired DevicePoll = "expired"
	// DeviceApproved: approved; the request is now redeemed and returned.
	DeviceApproved DevicePoll = "approved"
	// DeviceReused: the device code was already redeemed; the request is
	// returned so the grant it created can be revoked.
	DeviceReused DevicePoll = "reused"
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
	// and stores the code hash. clientRef is the stored client the request
	// now points to (a pending metadata-document client is stored first).
	// fullData records the person's choice to let the grant read all
	// organization data. A device request has no code: codeHash is "" and
	// the device code redeems the approval instead.
	ApproveRequest(ctx context.Context, id, userID, tenantID, clientRef shared.ID, granted []Scope, fullData bool, codeHash string, codeExpiresAt, now time.Time) error
	// ClaimDeviceRequest binds the pending, unexpired device request whose
	// user code hashes to userCodeHash to userID and returns it. A request
	// claimed by someone else, or none, is ErrNotFound. A device request
	// can be claimed only this way, never by its id.
	ClaimDeviceRequest(ctx context.Context, userCodeHash string, userID shared.ID, now time.Time) (*AuthRequest, error)
	// PollDeviceCode records a poll of the device code that hashes to
	// deviceCodeHash at now, atomically: a poll before the interval passed
	// grows the interval by DeviceSlowDownStep; an approved request is
	// moved to redeemed. The request is returned with every outcome. A code
	// unknown, or issued to another client than clientID, is ErrNotFound.
	PollDeviceCode(ctx context.Context, deviceCodeHash, clientID string, now time.Time) (*AuthRequest, DevicePoll, error)
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
	// RevokeGrantsByUser revokes every live grant of the user in EVERY
	// organization, deletes their tokens and cancels the user's pending or
	// approved authorization requests (an approved code must not be
	// redeemed after a credential change). It touches only that user. It
	// returns the number of grants revoked.
	RevokeGrantsByUser(ctx context.Context, userID shared.ID, reason string, now time.Time) (int, error)
	// SetGrantScoped turns a live grant that may read all organization
	// data back into a scoped one and reports whether a grant changed.
	SetGrantScoped(ctx context.Context, tenantID, grantID shared.ID) (bool, error)
	// TouchGrant records the last use of a grant.
	TouchGrant(ctx context.Context, tenantID, grantID shared.ID, ip string, now time.Time) error
}

// Connection is a grant as a list shows it, with the person it belongs to.
type Connection struct {
	Grant     Grant
	UserName  string
	UserEmail string
}

// ClientUsage is a client with its active connections (counts only).
type ClientUsage struct {
	Client            Client
	ActiveConnections int
	Organizations     int
	LastUsedAt        *time.Time
}

// ClientFilter narrows the platform's client list: Q matches part of the
// client_id (its host) or the declared name; Blocked keeps blocked (true) or
// unblocked (false) clients, nil keeps both.
type ClientFilter struct {
	Q       string
	Blocked *bool
}

// ConnectionRepository lists and manages connections (RFC-062 §12).
type ConnectionRepository interface {
	ListConnections(ctx context.Context, tenantID shared.ID, userID *shared.ID, now time.Time) ([]Connection, error)
	GetGrant(ctx context.Context, tenantID, grantID shared.ID) (*Grant, error)
	// ListClientsForPlatform and SetClientBlockedForPlatform serve the
	// platform admin console only.
	// ListClientsForPlatform returns one page (newest first) and the total
	// number of clients matching f.
	ListClientsForPlatform(ctx context.Context, f ClientFilter, limit, offset int, now time.Time) ([]ClientUsage, int, error)
	SetClientBlockedForPlatform(ctx context.Context, clientRef shared.ID, blocked bool, now time.Time) error
}

// Client id prefixes of registered clients (metadata-document clients are
// their URL).
const (
	OrganizationClientPrefix = "octc_"
	DynamicClientPrefix      = "octd_"
)

// ClientRepository manages registered clients (RFC-062 §5).
type ClientRepository interface {
	CreateClient(ctx context.Context, c *Client) (*Client, error)
	ListOrganizationClients(ctx context.Context, tenantID shared.ID) ([]Client, error)
	DeleteOrganizationClient(ctx context.Context, tenantID, id shared.ID) error
	// PurgeForPlatform deletes ended requests, tokens and grants and unused
	// clients (background job only).
	PurgeForPlatform(ctx context.Context, now time.Time) (int64, error)
}

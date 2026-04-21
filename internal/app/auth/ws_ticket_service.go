package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// F-8: Single-use WebSocket ticket service.
//
// Replaces the previous design of issuing a short-lived JWT and passing it as
// a ?token= query parameter. A JWT in a URL is still vulnerable to log /
// access-log / proxy / referer leakage within its TTL, which lets an attacker
// replay it. This ticket design closes that window:
//
//	1. IssueTicket mints a 32-byte random hex string stored in Redis with a
//	   very short TTL (default 30s) plus the owning user_id / tenant_id.
//	2. RedeemTicket performs an atomic GETDEL — success returns the claims
//	   exactly once. Any replay reads nothing and is rejected.
//
// The ticket itself carries no information (it is not a token) — it is only
// a lookup key. Leakage of the ticket only grants at-most-once WS upgrade
// within its TTL; any capture after the legitimate client has already
// upgraded is useless.

const (
	// wsTicketKeyPrefix namespaces ticket keys in Redis to avoid collisions.
	wsTicketKeyPrefix = "wsticket:"
	// wsTicketTTL is how long an unredeemed ticket stays valid.
	wsTicketTTL = 30 * time.Second
	// wsTicketBytes is the raw random-bytes length. 32 bytes -> 64 hex chars,
	// giving 256 bits of entropy — infeasible to brute-force during the TTL.
	wsTicketBytes = 32
)

// WSTicketStore is the minimal Redis surface the ticket service needs.
// Keeping this narrow makes testing easy and prevents coupling to the full
// Redis client surface.
type WSTicketStore interface {
	// Set stores value at key with TTL. Must overwrite existing keys
	// (the random ticket space is large enough that collisions are
	// negligible, and overwrite is safer than failing silently).
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// GetDel atomically reads and deletes a key, returning the stored value.
	// Returns ("", false, nil) when the key does not exist.
	GetDel(ctx context.Context, key string) (string, bool, error)
}

// WSTicketClaims is the payload persisted under each ticket. It is the minimum
// required to authenticate a WS upgrade as the issuing user/tenant.
type WSTicketClaims struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	IssuedAt int64  `json:"iat"`
}

// WSTicketService issues and redeems single-use WebSocket tickets.
type WSTicketService struct {
	store  WSTicketStore
	ttl    time.Duration
	logger *logger.Logger
}

// NewWSTicketService constructs the service. ttl defaults to 30s when zero.
func NewWSTicketService(store WSTicketStore, ttl time.Duration, log *logger.Logger) *WSTicketService {
	if ttl <= 0 {
		ttl = wsTicketTTL
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &WSTicketService{store: store, ttl: ttl, logger: log.With("service", "ws-ticket")}
}

// TTLSeconds returns the configured TTL in seconds for HTTP responses.
func (s *WSTicketService) TTLSeconds() int {
	return int(s.ttl / time.Second)
}

// IssueTicket mints a new opaque ticket and stores the caller's identity
// under it. The returned string is what the client passes as ?ticket= on the
// WebSocket upgrade.
func (s *WSTicketService) IssueTicket(ctx context.Context, userID, tenantID string) (string, error) {
	if userID == "" || tenantID == "" {
		return "", errors.New("user and tenant are required")
	}

	buf := make([]byte, wsTicketBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	ticket := hex.EncodeToString(buf)

	claims := WSTicketClaims{
		UserID:   userID,
		TenantID: tenantID,
		IssuedAt: time.Now().Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	if err := s.store.Set(ctx, wsTicketKeyPrefix+ticket, string(payload), s.ttl); err != nil {
		return "", fmt.Errorf("store ticket: %w", err)
	}
	return ticket, nil
}

// ErrTicketNotFound is returned by RedeemTicket when the ticket is missing,
// already consumed, or expired. Callers MUST treat all three the same (do not
// echo distinct error messages to the client — that would be an enumeration
// oracle).
var ErrTicketNotFound = errors.New("ws ticket not found")

// RedeemTicket atomically looks up and consumes a ticket. On success returns
// the claims it was issued with. ticket must be the raw opaque string
// returned from IssueTicket.
func (s *WSTicketService) RedeemTicket(ctx context.Context, ticket string) (*WSTicketClaims, error) {
	if ticket == "" {
		return nil, ErrTicketNotFound
	}
	// Basic shape check — our tickets are 64 hex chars. Skip the Redis
	// call for anything that obviously is not our format. This protects
	// the store from unbounded junk keys.
	if len(ticket) != wsTicketBytes*2 {
		return nil, ErrTicketNotFound
	}
	if _, err := hex.DecodeString(ticket); err != nil {
		return nil, ErrTicketNotFound
	}

	raw, ok, err := s.store.GetDel(ctx, wsTicketKeyPrefix+ticket)
	if err != nil {
		return nil, fmt.Errorf("getdel ticket: %w", err)
	}
	if !ok {
		return nil, ErrTicketNotFound
	}

	var claims WSTicketClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		s.logger.Warn("malformed ws ticket payload", "error", err)
		return nil, ErrTicketNotFound
	}
	if claims.UserID == "" || claims.TenantID == "" {
		return nil, ErrTicketNotFound
	}
	return &claims, nil
}

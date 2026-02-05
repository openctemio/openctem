package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/openctemio/api/pkg/logger"
)

const (
	// Key prefixes for token store.
	prefixBlacklist    = "blacklist"
	prefixSession      = "session"
	prefixRefreshToken = "refresh"
)

// TokenStore manages JWT tokens, sessions, and refresh tokens.
type TokenStore struct {
	client *Client
	logger *logger.Logger
}

// NewTokenStore creates a new token store.
func NewTokenStore(client *Client, log *logger.Logger) (*TokenStore, error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	if log == nil {
		return nil, errors.New("logger is required")
	}

	return &TokenStore{
		client: client,
		logger: log,
	}, nil
}

// MustNewTokenStore creates a token store or panics on error.
func MustNewTokenStore(client *Client, log *logger.Logger) *TokenStore {
	ts, err := NewTokenStore(client, log)
	if err != nil {
		panic(fmt.Sprintf("failed to create token store: %v", err))
	}
	return ts
}

// --- JWT Blacklist ---

// BlacklistToken adds a token to the blacklist.
// The token will be automatically removed after the expiry duration.
func (ts *TokenStore) BlacklistToken(ctx context.Context, jti string, expiry time.Duration) error {
	if jti == "" {
		return errors.New("jti is required")
	}
	if expiry <= 0 {
		return errors.New("expiry must be positive")
	}

	key := fmt.Sprintf("%s:%s", prefixBlacklist, jti)

	if err := ts.client.client.Set(ctx, key, "1", expiry).Err(); err != nil {
		return fmt.Errorf("blacklist token: %w", err)
	}

	ts.logger.Debug("token blacklisted", "jti", jti, "expiry", expiry)
	return nil
}

// IsBlacklisted checks if a token is blacklisted.
func (ts *TokenStore) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, errors.New("jti is required")
	}

	key := fmt.Sprintf("%s:%s", prefixBlacklist, jti)

	exists, err := ts.client.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("check blacklist: %w", err)
	}

	return exists > 0, nil
}

// --- Session Management ---

// SessionData represents session metadata.
type SessionData struct {
	UserID    string
	SessionID string
	UserAgent string
	IP        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Data      map[string]string
}

// StoreSession stores a user session atomically.
// All operations (HSet, Expire, SAdd) are executed in a transaction.
func (ts *TokenStore) StoreSession(ctx context.Context, userID, sessionID string, data map[string]string, ttl time.Duration) error {
	if userID == "" {
		return errors.New("userID is required")
	}
	if sessionID == "" {
		return errors.New("sessionID is required")
	}
	if ttl <= 0 {
		return errors.New("TTL must be positive")
	}

	key := fmt.Sprintf("%s:%s:%s", prefixSession, userID, sessionID)
	userSessionsKey := fmt.Sprintf("%s:%s:all", prefixSession, userID)

	// Atomic transaction - all or nothing
	pipe := ts.client.client.TxPipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, ttl)
	pipe.SAdd(ctx, userSessionsKey, sessionID)
	pipe.Expire(ctx, userSessionsKey, ttl) // Expire the set too

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store session: %w", err)
	}

	ts.logger.Debug("session stored", "user_id", userID, "session_id", sessionID)
	return nil
}

// GetSession retrieves a user session.
func (ts *TokenStore) GetSession(ctx context.Context, userID, sessionID string) (map[string]string, error) {
	if userID == "" {
		return nil, errors.New("userID is required")
	}
	if sessionID == "" {
		return nil, errors.New("sessionID is required")
	}

	key := fmt.Sprintf("%s:%s:%s", prefixSession, userID, sessionID)

	data, err := ts.client.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}

	if len(data) == 0 {
		return nil, ErrKeyNotFound
	}

	return data, nil
}

// DeleteSession removes a user session atomically.
func (ts *TokenStore) DeleteSession(ctx context.Context, userID, sessionID string) error {
	if userID == "" {
		return errors.New("userID is required")
	}
	if sessionID == "" {
		return errors.New("sessionID is required")
	}

	key := fmt.Sprintf("%s:%s:%s", prefixSession, userID, sessionID)
	userSessionsKey := fmt.Sprintf("%s:%s:all", prefixSession, userID)

	// Atomic transaction
	pipe := ts.client.client.TxPipeline()
	pipe.Del(ctx, key)
	pipe.SRem(ctx, userSessionsKey, sessionID)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	ts.logger.Debug("session deleted", "user_id", userID, "session_id", sessionID)
	return nil
}

// deleteAllFromSet is a helper that deletes all items from a set and their associated keys.
// Used by DeleteAllUserSessions and RevokeAllRefreshTokens to avoid code duplication.
func (ts *TokenStore) deleteAllFromSet(ctx context.Context, setKey, keyPrefix, userID, operationName string) (int, error) {
	// Get all members from the set
	members, err := ts.client.client.SMembers(ctx, setKey).Result()
	if err != nil {
		return 0, fmt.Errorf("get %s: %w", operationName, err)
	}

	if len(members) == 0 {
		return 0, nil
	}

	// Atomic transaction - delete all items and the set
	pipe := ts.client.client.TxPipeline()
	for _, member := range members {
		key := fmt.Sprintf("%s:%s:%s", keyPrefix, userID, member)
		pipe.Del(ctx, key)
	}
	pipe.Del(ctx, setKey)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("delete %s: %w", operationName, err)
	}

	return len(members), nil
}

// DeleteAllUserSessions removes all sessions for a user atomically.
func (ts *TokenStore) DeleteAllUserSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("userID is required")
	}

	userSessionsKey := fmt.Sprintf("%s:%s:all", prefixSession, userID)
	count, err := ts.deleteAllFromSet(ctx, userSessionsKey, prefixSession, userID, "user sessions")
	if err != nil {
		return err
	}

	if count > 0 {
		ts.logger.Info("all sessions deleted", "user_id", userID, "count", count)
	}
	return nil
}

// GetUserSessions returns all active session IDs for a user.
func (ts *TokenStore) GetUserSessions(ctx context.Context, userID string) ([]string, error) {
	if userID == "" {
		return nil, errors.New("userID is required")
	}

	userSessionsKey := fmt.Sprintf("%s:%s:all", prefixSession, userID)

	sessionIDs, err := ts.client.client.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("get user sessions: %w", err)
	}

	return sessionIDs, nil
}

// refreshSessionScript atomically checks session existence and extends TTL.
var refreshSessionScript = redis.NewScript(`
	local session_key = KEYS[1]
	local user_sessions_key = KEYS[2]
	local ttl_ms = tonumber(ARGV[1])

	-- Check if session exists
	local exists = redis.call('EXISTS', session_key)
	if exists == 0 then
		return 0
	end

	-- Extend TTL for both keys
	redis.call('PEXPIRE', session_key, ttl_ms)
	redis.call('PEXPIRE', user_sessions_key, ttl_ms)

	return 1
`)

// RefreshSession extends the TTL of a session atomically.
// Uses Lua scripting to prevent race conditions between existence check and TTL update.
func (ts *TokenStore) RefreshSession(ctx context.Context, userID, sessionID string, ttl time.Duration) error {
	if userID == "" {
		return errors.New("userID is required")
	}
	if sessionID == "" {
		return errors.New("sessionID is required")
	}
	if ttl <= 0 {
		return errors.New("TTL must be positive")
	}

	key := fmt.Sprintf("%s:%s:%s", prefixSession, userID, sessionID)
	userSessionsKey := fmt.Sprintf("%s:%s:all", prefixSession, userID)

	// Atomic check-and-update using Lua script
	result, err := refreshSessionScript.Run(ctx, ts.client.client,
		[]string{key, userSessionsKey},
		ttl.Milliseconds(),
	).Int64()
	if err != nil {
		return fmt.Errorf("refresh session: %w", err)
	}

	if result == 0 {
		return ErrKeyNotFound
	}

	return nil
}

// --- Refresh Tokens ---

// StoreRefreshToken stores a refresh token hash atomically.
func (ts *TokenStore) StoreRefreshToken(ctx context.Context, userID, tokenHash string, ttl time.Duration) error {
	if userID == "" {
		return errors.New("userID is required")
	}
	if tokenHash == "" {
		return errors.New("tokenHash is required")
	}
	if ttl <= 0 {
		return errors.New("TTL must be positive")
	}

	key := fmt.Sprintf("%s:%s:%s", prefixRefreshToken, userID, tokenHash)
	userTokensKey := fmt.Sprintf("%s:%s:all", prefixRefreshToken, userID)

	// Atomic transaction
	pipe := ts.client.client.TxPipeline()
	pipe.Set(ctx, key, "1", ttl)
	pipe.SAdd(ctx, userTokensKey, tokenHash)
	pipe.Expire(ctx, userTokensKey, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}

	ts.logger.Debug("refresh token stored", "user_id", userID)
	return nil
}

// ValidateRefreshToken checks if a refresh token is valid.
func (ts *TokenStore) ValidateRefreshToken(ctx context.Context, userID, tokenHash string) (bool, error) {
	if userID == "" {
		return false, errors.New("userID is required")
	}
	if tokenHash == "" {
		return false, errors.New("tokenHash is required")
	}

	key := fmt.Sprintf("%s:%s:%s", prefixRefreshToken, userID, tokenHash)

	exists, err := ts.client.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("validate refresh token: %w", err)
	}

	return exists > 0, nil
}

// RevokeRefreshToken removes a refresh token atomically.
func (ts *TokenStore) RevokeRefreshToken(ctx context.Context, userID, tokenHash string) error {
	if userID == "" {
		return errors.New("userID is required")
	}
	if tokenHash == "" {
		return errors.New("tokenHash is required")
	}

	key := fmt.Sprintf("%s:%s:%s", prefixRefreshToken, userID, tokenHash)
	userTokensKey := fmt.Sprintf("%s:%s:all", prefixRefreshToken, userID)

	// Atomic transaction
	pipe := ts.client.client.TxPipeline()
	pipe.Del(ctx, key)
	pipe.SRem(ctx, userTokensKey, tokenHash)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	ts.logger.Debug("refresh token revoked", "user_id", userID)
	return nil
}

// RevokeAllRefreshTokens revokes all refresh tokens for a user atomically.
func (ts *TokenStore) RevokeAllRefreshTokens(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("userID is required")
	}

	userTokensKey := fmt.Sprintf("%s:%s:all", prefixRefreshToken, userID)
	count, err := ts.deleteAllFromSet(ctx, userTokensKey, prefixRefreshToken, userID, "refresh tokens")
	if err != nil {
		return err
	}

	if count > 0 {
		ts.logger.Info("all refresh tokens revoked", "user_id", userID, "count", count)
	}
	return nil
}

// RotateRefreshToken atomically revokes old token and stores new one.
func (ts *TokenStore) RotateRefreshToken(ctx context.Context, userID, oldTokenHash, newTokenHash string, ttl time.Duration) error {
	if userID == "" {
		return errors.New("userID is required")
	}
	if oldTokenHash == "" {
		return errors.New("oldTokenHash is required")
	}
	if newTokenHash == "" {
		return errors.New("newTokenHash is required")
	}
	if ttl <= 0 {
		return errors.New("TTL must be positive")
	}

	oldKey := fmt.Sprintf("%s:%s:%s", prefixRefreshToken, userID, oldTokenHash)
	newKey := fmt.Sprintf("%s:%s:%s", prefixRefreshToken, userID, newTokenHash)
	userTokensKey := fmt.Sprintf("%s:%s:all", prefixRefreshToken, userID)

	// Atomic transaction - revoke old and store new
	pipe := ts.client.client.TxPipeline()
	pipe.Del(ctx, oldKey)
	pipe.SRem(ctx, userTokensKey, oldTokenHash)
	pipe.Set(ctx, newKey, "1", ttl)
	pipe.SAdd(ctx, userTokensKey, newTokenHash)
	pipe.Expire(ctx, userTokensKey, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("rotate refresh token: %w", err)
	}

	ts.logger.Debug("refresh token rotated", "user_id", userID)
	return nil
}

// CountActiveSessions returns the number of active sessions for a user.
func (ts *TokenStore) CountActiveSessions(ctx context.Context, userID string) (int64, error) {
	if userID == "" {
		return 0, errors.New("userID is required")
	}

	userSessionsKey := fmt.Sprintf("%s:%s:all", prefixSession, userID)

	count, err := ts.client.client.SCard(ctx, userSessionsKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return 0, fmt.Errorf("count sessions: %w", err)
	}

	return count, nil
}

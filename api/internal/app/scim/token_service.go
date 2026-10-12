// Package scim implements SCIM 2.0 provisioning (RFC-009): per-tenant bearer
// tokens and the User provisioning that maps SCIM operations onto OpenCTEM
// users + tenant memberships.
package scim

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/scimtoken"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// tokenPlaintextPrefix is the human-recognizable prefix of a SCIM bearer token.
const tokenPlaintextPrefix = "oct_scim_"

// TokenService mints, lists, revokes, and authenticates SCIM bearer tokens.
// Tokens are stored as peppered HMAC-SHA256 hashes (see crypto.HashTokenPeppered)
// exactly like API keys — a DB leak without APP_ENCRYPTION_KEY cannot be
// brute-forced offline.
type TokenService struct {
	repo   scimtoken.Repository
	pepper string
	legacy []string // earlier peppers that still verify (key rotation)
	logger *logger.Logger
	now    func() time.Time
}

// NewTokenService wires the service. pepper should be APP_ENCRYPTION_KEY.
func NewTokenService(repo scimtoken.Repository, pepper string, log *logger.Logger) *TokenService {
	return &TokenService{
		repo:   repo,
		pepper: pepper,
		logger: log.With("service", "scim-token"),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// SetLegacyPeppers sets earlier peppers whose token hashes keep verifying
// while APP_ENCRYPTION_KEY rotates (APP_ENCRYPTION_KEY_PREVIOUS). New tokens
// are always hashed with the current pepper.
func (s *TokenService) SetLegacyPeppers(peppers ...string) {
	s.legacy = s.legacy[:0]
	for _, p := range peppers {
		if p != "" && p != s.pepper {
			s.legacy = append(s.legacy, p)
		}
	}
}

// TokenRehasher is implemented by a repository that can replace a token hash
// made with an earlier pepper (compare-and-swap on the old hash).
type TokenRehasher interface {
	RehashKey(ctx context.Context, id shared.ID, oldHash, newHash string) (bool, error)
}

// MintResult carries the plaintext, which is shown to the admin exactly once.
type MintResult struct {
	Token     *scimtoken.ScimToken
	Plaintext string
}

// Mint creates a new SCIM bearer token for a tenant.
func (s *TokenService) Mint(ctx context.Context, tenantID shared.ID, name string, createdBy *shared.ID) (*MintResult, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant id required", shared.ErrValidation)
	}
	if name == "" {
		name = "SCIM token"
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate scim token: %w", err)
	}
	plaintext := tokenPlaintextPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hash := crypto.HashTokenPeppered(plaintext, s.pepper)
	prefix := plaintext[:len(tokenPlaintextPrefix)+4]

	tok := scimtoken.New(shared.NewID(), tenantID, name, hash, prefix)
	if createdBy != nil && !createdBy.IsZero() {
		tok.SetCreatedBy(*createdBy)
	}
	if err := s.repo.Create(ctx, tok); err != nil {
		return nil, err
	}
	s.logger.Info("scim token minted", "tenant_id", tenantID.String(), "token_id", tok.ID().String())
	return &MintResult{Token: tok, Plaintext: plaintext}, nil
}

// List returns a tenant's SCIM tokens (metadata only; never the plaintext/hash).
func (s *TokenService) List(ctx context.Context, tenantID shared.ID) ([]*scimtoken.ScimToken, error) {
	return s.repo.ListByTenant(ctx, tenantID)
}

// Revoke marks a tenant's token unusable.
func (s *TokenService) Revoke(ctx context.Context, tenantID, id shared.ID) error {
	tok, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return err
	}
	tok.Revoke()
	return s.repo.Update(ctx, tok)
}

// Authenticate validates a presented bearer token and returns it when active.
// Any invalid/revoked/unknown token returns scimtoken.ErrNotFound without
// distinction, so the caller cannot enumerate tokens.
func (s *TokenService) Authenticate(ctx context.Context, plaintext string) (*scimtoken.ScimToken, error) {
	if plaintext == "" {
		return nil, scimtoken.ErrNotFound
	}
	hash := crypto.HashTokenPeppered(plaintext, s.pepper)
	tok, err := s.repo.GetByHash(ctx, hash)
	matched := hash
	for _, p := range s.legacy {
		if err == nil {
			break
		}
		matched = crypto.HashTokenPeppered(plaintext, p)
		tok, err = s.repo.GetByHash(ctx, matched)
	}
	if err != nil || !tok.IsActive() {
		return nil, scimtoken.ErrNotFound
	}
	// A token that matched under an earlier pepper is re-hashed with the
	// current one, so it stops depending on APP_ENCRYPTION_KEY_PREVIOUS.
	if matched != hash {
		if r, ok := s.repo.(TokenRehasher); ok {
			if _, rerr := r.RehashKey(ctx, tok.ID(), matched, hash); rerr != nil {
				s.logger.Warn("scim token re-hash under the current pepper failed", "token_id", tok.ID().String(), "error", rerr)
			}
		}
	}
	// Best-effort last-used stamp (non-fatal). Uses a status-preserving,
	// active-only update so a concurrent revoke is never clobbered.
	if uerr := s.repo.TouchLastUsed(ctx, tok.TenantID(), tok.ID(), s.now()); uerr != nil {
		s.logger.Warn("scim token touch failed", "token_id", tok.ID().String(), "error", uerr)
	}
	return tok, nil
}

package contentsource

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"time"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// sealedCredential is what credential_encrypted holds once decrypted. The
// source id, tenant and host bind the ciphertext to its row: a value copied
// to another source, another organization or used after the host changed
// does not open.
type sealedCredential struct {
	V        int    `json:"v"`
	SourceID string `json:"sid"`
	TenantID string `json:"tid"`
	Host     string `json:"host"`
	Token    string `json:"t"`
}

func tenantString(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func (s *Service) seal(src *dom.Source, token string) (string, error) {
	if s.enc == nil {
		return "", fmt.Errorf("%w: credential encryption is not configured", shared.ErrInternal)
	}
	raw, err := json.Marshal(sealedCredential{V: 1, SourceID: src.ID.String(), TenantID: tenantString(src.TenantID), Host: src.Host(), Token: token})
	if err != nil {
		return "", err
	}
	return s.enc.EncryptString(string(raw))
}

// errCredentialUnusable: the stored credential does not open for this
// source (wrong key, or bound to another source or host). It is never used.
var errCredentialUnusable = errors.New("the stored credential cannot be used; set it again")

func (s *Service) unseal(src *dom.Source) (string, error) {
	if !src.HasCredential() {
		return "", nil
	}
	if s.enc == nil {
		return "", errCredentialUnusable
	}
	plain, err := s.enc.DecryptString(src.CredentialEncrypted)
	if err != nil {
		return "", errCredentialUnusable
	}
	var c sealedCredential
	if err := json.Unmarshal([]byte(plain), &c); err != nil || c.V != 1 {
		return "", errCredentialUnusable
	}
	if c.SourceID != src.ID.String() || c.TenantID != tenantString(src.TenantID) || c.Host != src.Host() {
		return "", errCredentialUnusable
	}
	return c.Token, nil
}

// SetCredential stores the fetch credential of an organization source:
// write-only, encrypted, bound to the source and its host. The username
// defaults by token type (a deploy token needs its own). Setting it counts
// as a change of what the source fetches (four-eyes).
func (s *Service) SetCredential(ctx context.Context, a Actor, id shared.ID, username, token string) (*dom.Source, error) {
	src, err := s.ownSource(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	if err := dom.ValidateToken(token); err != nil {
		return nil, err
	}
	user, err := dom.ResolveUsername(username, token)
	if err != nil {
		return nil, err
	}
	sealed, err := s.seal(src, token)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	src.SetCredential(user, sealed, dom.TokenHint(token), now)
	src.MarkConfigChanged(a.UserID, now)
	if err := s.repo.Update(ctx, src); err != nil {
		return nil, err
	}
	if src.Enabled {
		_ = s.repo.RequestSync(ctx, a.TenantID, src.ID, now)
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceCredentialSet, src,
		fmt.Sprintf("Credential of rule source '%s' set (sent only to %s)", src.Slug, src.Host())).
		WithMetadata("username", user))
	return src, nil
}

// ClearCredential removes the stored credential.
func (s *Service) ClearCredential(ctx context.Context, a Actor, id shared.ID) (*dom.Source, error) {
	src, err := s.ownSource(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	if !src.HasCredential() {
		return src, nil
	}
	src.ClearCredential()
	src.MarkConfigChanged(a.UserID, s.now().UTC())
	if err := s.repo.Update(ctx, src); err != nil {
		return nil, err
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceCredentialCleared, src,
		fmt.Sprintf("Credential of rule source '%s' removed", src.Slug)).WithMetadata("reason", "removed"))
	return src, nil
}

// --- webhook ----------------------------------------------------------------

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// RotateWebhookSecret turns the webhook on (or rotates its secret) and
// returns the new secret once; only its hash is stored. It needs the
// webhook feature.
func (s *Service) RotateWebhookSecret(ctx context.Context, a Actor, id shared.ID) (string, error) {
	src, err := s.ownSource(ctx, a.TenantID, id)
	if err != nil {
		return "", err
	}
	if err := s.requireFeature(ctx, a.TenantID, limits.FeatureContentWebhook); err != nil {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate webhook secret: %w", err)
	}
	secret := "ocws_" + base64.RawURLEncoding.EncodeToString(buf)
	now := s.now().UTC()
	src.WebhookSecretHash, src.WebhookSecretAt = hashSecret(secret), &now
	if err := s.repo.Update(ctx, src); err != nil {
		return "", err
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceWebhookSet, src,
		fmt.Sprintf("Webhook secret of rule source '%s' set", src.Slug)).WithMetadata("enabled", true))
	return secret, nil
}

// DisableWebhook removes the webhook secret: calls are refused.
func (s *Service) DisableWebhook(ctx context.Context, a Actor, id shared.ID) error {
	src, err := s.ownSource(ctx, a.TenantID, id)
	if err != nil {
		return err
	}
	if src.WebhookSecretHash == "" {
		return nil
	}
	src.WebhookSecretHash, src.WebhookSecretAt = "", nil
	if err := s.repo.Update(ctx, src); err != nil {
		return err
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceWebhookSet, src,
		fmt.Sprintf("Webhook of rule source '%s' turned off", src.Slug)).WithMetadata("enabled", false))
	return nil
}

// ErrWebhookRejected is the one answer to a webhook call that does not
// queue a sync for any reason the caller must not learn (unknown source,
// wrong secret, webhook off, feature denied).
var ErrWebhookRejected = shared.NewDomainError("WEBHOOK_REJECTED", "webhook rejected", shared.ErrUnauthorized)

// HandleWebhook queues a sync of the source when secret matches its webhook
// secret (constant time). The call carries no content: it only queues a
// sync, at most one per minute and WebhookCallsPerHour an hour per source.
func (s *Service) HandleWebhook(ctx context.Context, id shared.ID, secret string) error {
	src, err := s.repo.GetUnscoped(ctx, id)
	if err != nil || src.WebhookSecretHash == "" || secret == "" {
		return ErrWebhookRejected
	}
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(src.WebhookSecretHash)) != 1 {
		return ErrWebhookRejected
	}
	if !src.Enabled || src.IsPlatform() {
		return ErrWebhookRejected
	}
	if src.TenantID != nil && !s.featureUsable(ctx, *src.TenantID, limits.FeatureContentWebhook) {
		return ErrWebhookRejected
	}
	if !s.hookLimit.allow(src.ID.String(), s.now()) {
		return dom.ErrRateLimited
	}
	if _, err := s.repo.RequestSyncUnscoped(ctx, src.ID, s.now().UTC(), time.Minute); err != nil {
		return err
	}
	return nil
}

// --- small helpers ------------------------------------------------------------

func randomJitter() float64 { return mrand.Float64() } //nolint:gosec // schedule spread, not security

// windowLimiter is a fixed-window counter per key, in process. It is an
// instance safety limit (abuse brake), not an accounting limit.
type windowLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	seen   map[string]windowCount
}

type windowCount struct {
	start time.Time
	n     int
}

func newWindowLimiter(max int, window time.Duration) *windowLimiter {
	return &windowLimiter{max: max, window: window, seen: map[string]windowCount{}}
}

func (l *windowLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 100000 {
		l.seen = map[string]windowCount{}
	}
	c := l.seen[key]
	if now.Sub(c.start) >= l.window {
		c = windowCount{start: now}
	}
	if c.n >= l.max {
		return false
	}
	c.n++
	l.seen[key] = c
	return true
}

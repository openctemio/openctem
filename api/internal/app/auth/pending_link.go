package auth

// Pending link: linking a social identity to an existing account after the
// person signs in to that account (docs/architecture/social-login-linking.md).
//
// A social sign-in whose provider-verified address belongs to an account that
// signs in another way changes nothing on that account. It is refused with
// OAUTH_ACCOUNT_EXISTS and leaves a pending link: the provider identity
// (issuer, subject) and the account it collided with, kept server side for
// pendingLinkTTL under the hash of a random secret. The secret goes to the
// browser that made the sign-in (the web server keeps it in an HttpOnly
// cookie) and nowhere else.
//
// The person then signs in to the account the usual way: password and second
// factor, or the provider the account already uses. Only that account, from a
// session that authenticated after the pending link was made (a sign-in or a
// step-up, checked against the session's own record), with the secret and a
// proof typed in the confirm dialog (an authenticator code, else the
// password; link_proof.go), may confirm it; the link then follows the explicit-link rules (linkIdentity),
// every other session of the account is revoked, the link is audited and the
// account's mailbox is told. The record is single use: confirming, canceling
// or presenting it from another account spends it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
)

// pendingLinkTTL is how long a pending link waits for the person to sign in
// and confirm it.
const pendingLinkTTL = 10 * time.Minute

const pendingLinkKeyPrefix = "oauth_pending_link:"

// maxPendingLinkToken bounds the secret a client presents (base64url of 32
// bytes is 43 characters).
const maxPendingLinkToken = 128

// ErrPendingLinkInvalid: there is no pending link for this secret and this
// account (expired, spent, made for another account, or never made). One
// answer for every case.
var ErrPendingLinkInvalid = errors.New("there is no sign-in method waiting to be linked to this account")

// ErrPendingLinkNeedsSignIn: the session did not sign in (or step up) after
// the pending link was made.
var ErrPendingLinkNeedsSignIn = errors.New("sign in to the account again to link this sign-in method")

// PendingLinkError is ErrOAuthAccountExists with a pending link the web
// server keeps for the browser (an HttpOnly cookie). errors.Is(err,
// ErrOAuthAccountExists) holds.
type PendingLinkError struct {
	// Token is the secret of the pending link. Only its hash is stored.
	Token    string
	Provider OAuthProvider
}

func (e *PendingLinkError) Error() string { return ErrOAuthAccountExists.Error() }

// Unwrap makes errors.Is(err, ErrOAuthAccountExists) hold.
func (e *PendingLinkError) Unwrap() error { return ErrOAuthAccountExists }

// pendingLink is the stored record.
type pendingLink struct {
	UserID        string        `json:"user_id"`
	Provider      OAuthProvider `json:"provider"`
	Issuer        string        `json:"issuer"`
	Subject       string        `json:"subject"`
	LegacySubject string        `json:"legacy_subject,omitempty"`
	Email         string        `json:"email"`
	CreatedAt     time.Time     `json:"created_at"`
}

func (p *pendingLink) expiresAt() time.Time { return p.CreatedAt.Add(pendingLinkTTL) }

// PendingLinkInfo describes a pending link to the account it was made for.
type PendingLinkInfo struct {
	Provider string `json:"provider"`
	// Email is the provider account's address (the account's own address:
	// the pending link was made because they are the same).
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
	// Proof is what confirming asks for: totp, password, or "" when the
	// account has neither (it must turn on two-factor authentication first).
	Proof string `json:"proof"`
}

func pendingLinkKey(token string) string { return pendingLinkKeyPrefix + hashBinding(token) }

// offerPendingLink answers a social sign-in refused because its address
// belongs to u, an account that signs in another way. When the identity could
// be linked to u, it stores a pending link and returns a *PendingLinkError;
// otherwise (or when storing fails) the plain ErrOAuthAccountExists. Nothing
// on the account changes either way.
func (s *OAuthService) offerPendingLink(ctx context.Context, u *userdom.User, info *OAuthUserInfo, provider OAuthProvider) error {
	key := useridentity.Key{Issuer: info.Issuer, Subject: info.Subject}
	if !key.Valid() || !u.IsActive() || s.pkceStore == nil || providerOfKey(key) != provider {
		return ErrOAuthAccountExists
	}
	if err := s.checkLinkable(ctx, u, key, provider); err != nil {
		return ErrOAuthAccountExists
	}
	token, err := newBrowserBinding()
	if err != nil {
		s.logger.Error("pending link: secret generation failed", "error", err)
		return ErrOAuthAccountExists
	}
	rec := pendingLink{
		UserID: u.ID().String(), Provider: provider,
		Issuer: key.Issuer, Subject: key.Subject, LegacySubject: info.LegacySubject,
		Email: strings.TrimSpace(info.Email), CreatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return ErrOAuthAccountExists
	}
	if err := s.pkceStore.Set(ctx, pendingLinkKey(token), string(raw), pendingLinkTTL); err != nil {
		s.logger.Error("pending link: store failed", "error", err)
		return ErrOAuthAccountExists
	}
	s.logger.Info("social sign-in refused: the address has an account; pending link offered",
		"user_id", u.ID().String(), "provider", provider)
	return &PendingLinkError{Token: token, Provider: provider}
}

// takePendingLink removes and returns the pending link for token when it was
// made for userID. A pending link presented by another account is spent and
// refused.
func (s *OAuthService) takePendingLink(ctx context.Context, userID, token string) (*pendingLink, error) {
	if token == "" || len(token) > maxPendingLinkToken || userID == "" || s.pkceStore == nil {
		return nil, ErrPendingLinkInvalid
	}
	raw, found, err := s.pkceStore.GetDel(ctx, pendingLinkKey(token))
	if err != nil {
		return nil, fmt.Errorf("read pending link: %w", err)
	}
	if !found {
		return nil, ErrPendingLinkInvalid
	}
	var rec pendingLink
	if err := json.Unmarshal([]byte(raw), &rec); err != nil || rec.UserID == "" || !rec.Provider.IsValid() {
		return nil, ErrPendingLinkInvalid
	}
	if rec.UserID != userID {
		s.logger.Warn("pending link presented by another account; spent", "user_id", userID)
		return nil, ErrPendingLinkInvalid
	}
	if !time.Now().Before(rec.expiresAt()) {
		return nil, ErrPendingLinkInvalid
	}
	return &rec, nil
}

// DescribePendingLink tells the signed-in account which provider account is
// waiting to be linked to it. It does not spend the pending link, except when
// another account presents it.
func (s *OAuthService) DescribePendingLink(ctx context.Context, userID, token string) (*PendingLinkInfo, error) {
	rec, err := s.takePendingLink(ctx, userID, token)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("encode pending link: %w", err)
	}
	if left := time.Until(rec.expiresAt()); left > 0 {
		if err := s.pkceStore.Set(ctx, pendingLinkKey(token), string(raw), left); err != nil {
			return nil, fmt.Errorf("keep pending link: %w", err)
		}
	}
	return &PendingLinkInfo{Provider: string(rec.Provider), Email: rec.Email, ExpiresAt: rec.expiresAt(), Proof: s.linkProofMethod(ctx, userID)}, nil
}

// CancelPendingLink drops a pending link ("not now"). Always succeeds.
func (s *OAuthService) CancelPendingLink(ctx context.Context, userID, token string) {
	if _, err := s.takePendingLink(ctx, userID, token); err == nil {
		s.logger.Info("pending link declined", "user_id", userID)
	}
}

// ConfirmPendingLinkInput confirms a pending link from the signed-in account.
type ConfirmPendingLinkInput struct {
	UserID    string
	SessionID string
	Token     string
	// Proof is the code or password typed in the confirm dialog
	// (link_proof.go). The sign-in that just happened does not count.
	Proof StepUpProof
}

// ConfirmPendingLink links the pending provider identity to the signed-in
// account. It needs the proof typed in the confirm dialog, checked before the
// pending link is taken (a mistyped code leaves it for another try), and a
// session that authenticated after the pending link was made.
func (s *OAuthService) ConfirmPendingLink(ctx context.Context, in ConfirmPendingLinkInput) (*SignInMethod, error) {
	if in.SessionID == "" {
		return nil, ErrPendingLinkInvalid
	}
	owner, _, err := s.accountAndIdentities(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	factor, err := s.verifyLinkProof(ctx, owner, in.SessionID, in.Proof, LinkProofPendingLink)
	if err != nil {
		return nil, err
	}
	rec, err := s.takePendingLink(ctx, in.UserID, in.Token)
	if err != nil {
		return nil, err
	}
	if !rec.Provider.IsValid() {
		return nil, ErrPendingLinkInvalid
	}
	if err := s.authenticatedSince(ctx, in.UserID, in.SessionID, rec.CreatedAt); err != nil {
		return nil, err
	}
	u, _, err := s.accountAndIdentities(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	// The pending link was made because the provider's address is the
	// account's. An account whose address changed since is not the one the
	// provider vouched for.
	if !strings.EqualFold(strings.TrimSpace(u.Email()), rec.Email) {
		return nil, ErrPendingLinkInvalid
	}
	info := &OAuthUserInfo{Email: rec.Email, Issuer: rec.Issuer, Subject: rec.Subject, LegacySubject: rec.LegacySubject}
	m, err := s.linkIdentity(ctx, in.UserID, info, rec.Provider, linkHowAfterSignIn, factor)
	if err != nil {
		return nil, err
	}
	// Whoever else held a session of the account loses it; the person who
	// just signed in and confirmed keeps theirs.
	if s.sessions != nil {
		if rerr := s.sessions.RevokeAllSessions(ctx, in.UserID, in.SessionID); rerr != nil {
			s.logger.Error("pending link: revoking the account's other sessions failed", "user_id", in.UserID, "error", rerr)
		}
	}
	return m, nil
}

// authenticatedSince checks that the session proved the person (a sign-in or
// a step-up, from the session's own server-side record) at or after since.
// Fail closed: without the session record nothing is linked.
func (s *OAuthService) authenticatedSince(ctx context.Context, userID, sessionID string, since time.Time) error {
	store, ok := s.sessionRepo.(StepUpSessionStore)
	if !ok || store == nil {
		return ErrPendingLinkNeedsSignIn
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return ErrPendingLinkInvalid
	}
	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return ErrPendingLinkInvalid
	}
	at, err := store.RecentAuthAt(ctx, sid, uid)
	if err != nil {
		return ErrPendingLinkNeedsSignIn
	}
	// The session row stores times at microsecond precision; allow for it.
	if at.Before(since.Truncate(time.Second)) {
		return ErrPendingLinkNeedsSignIn
	}
	return nil
}

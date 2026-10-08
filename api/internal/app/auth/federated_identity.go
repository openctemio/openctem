package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// Federated accounts are keyed on the identity provider's user id, the
// (issuer, subject) pair, not on the email address (research/72 GA19).
//
//   - A login first looks the account up by the pair. A match is the account,
//     whatever email the provider now sends: an email changed at the provider
//     moves with the account instead of creating a second one or being
//     refused.
//   - Only when the pair is unknown does the email find an account, under the
//     existing adoption guards, and the pair is then bound to it. The binding
//     is refused when the account already holds a different subject from the
//     same issuer: that is a second person (or an attacker's directory)
//     presenting the same email, never the same account.
//
// Threat model: users are global, so a pair that resolves to an account
// grants a session that every organization of the account honors. An OIDC
// pair is platform-wide only because the issuer signs it with keys only the
// issuer holds (verified id_token) or the provider's own API returned it
// (social login). A SAML pair is signed with a certificate the organization
// configured, so it is scoped to that organization (Key.ScopeTenantID) and
// never resolves an account outside it.

// ErrFederatedIdentityConflict refuses a login whose email names an account
// already bound to a different subject at the same identity provider.
var ErrFederatedIdentityConflict = errors.New("this email is registered with a different account at this identity provider")

// errIdentityStoreMissing fails a federated login closed when the identity
// store is not wired: without it the account cannot be matched by subject.
var errIdentityStoreMissing = errors.New("federated identity store not configured")

// federatedAccounts resolves and binds federated identities. Shared by the
// organization SSO paths (OIDC, SAML) and social login.
type federatedAccounts struct {
	identities useridentity.Repository
	users      userdom.Repository
	logger     *logger.Logger
}

// lookup returns the account bound to key, or (nil, nil, nil) when none is.
// legacySubject is a subject the same issuer used before for the identity
// (Entra: `sub` before the account was keyed on `oid`); a row found under it
// is re-keyed to key.Subject.
func (f federatedAccounts) lookup(ctx context.Context, key useridentity.Key, legacySubject string) (*userdom.User, *useridentity.Identity, error) {
	if f.identities == nil {
		return nil, nil, errIdentityStoreMissing
	}
	ident, err := f.identities.GetByKey(ctx, key)
	if errors.Is(err, useridentity.ErrNotFound) && legacySubject != "" && legacySubject != key.Subject {
		legacy := key
		legacy.Subject = legacySubject
		ident, err = f.identities.GetByKey(ctx, legacy)
		if err == nil {
			if cerr := f.identities.ChangeSubject(ctx, ident.ID, key.Subject); cerr != nil {
				return nil, nil, fmt.Errorf("re-key federated identity: %w", cerr)
			}
			ident.Key.Subject = key.Subject
		}
	}
	if errors.Is(err, useridentity.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	u, err := f.users.GetByID(ctx, ident.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("load account of federated identity: %w", err)
	}
	return u, ident, nil
}

// boundIdentities reports what u already has bound: a different subject from
// key's issuer (sameIssuer), and any platform-wide identity from another
// issuer (otherIssuer, nil when none).
func (f federatedAccounts) boundIdentities(ctx context.Context, u *userdom.User, key useridentity.Key) (sameIssuer bool, otherIssuer *useridentity.Identity, err error) {
	if f.identities == nil {
		return false, nil, errIdentityStoreMissing
	}
	idents, err := f.identities.ListByUser(ctx, u.ID())
	if err != nil {
		return false, nil, err
	}
	for _, ident := range idents {
		switch {
		case ident.Key.SameIssuer(key):
			if ident.Key.Subject != key.Subject {
				sameIssuer = true
			}
		case ident.Key.ScopeTenantID == nil && otherIssuer == nil:
			otherIssuer = ident
		}
	}
	return sameIssuer, otherIssuer, nil
}

// bind records key on u. The unique indexes make this the final arbiter: a
// pair bound elsewhere, or a second subject from the issuer, is refused.
func (f federatedAccounts) bind(ctx context.Context, u *userdom.User, key useridentity.Key) error {
	if f.identities == nil {
		return errIdentityStoreMissing
	}
	ident, err := useridentity.New(u.ID(), key)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	ident.LastUsedAt = &now
	if err := f.identities.Create(ctx, ident); err != nil {
		if errors.Is(err, useridentity.ErrConflict) {
			// A concurrent first login may have bound the same pair to this
			// same account: that is not a conflict.
			if got, gerr := f.identities.GetByKey(ctx, key); gerr == nil && got.UserID == u.ID() {
				return nil
			}
			return ErrFederatedIdentityConflict
		}
		return fmt.Errorf("bind federated identity: %w", err)
	}
	f.logger.Info("federated identity bound to account", "user_id", u.ID().String(), "issuer", key.Issuer)
	return nil
}

// markUsed records the sign-in; a failure is logged, never fatal.
func (f federatedAccounts) markUsed(ctx context.Context, ident *useridentity.Identity) {
	if ident == nil || f.identities == nil {
		return
	}
	if err := f.identities.MarkUsed(ctx, ident.ID, time.Now().UTC()); err != nil {
		f.logger.Warn("record federated identity use", "error", err)
	}
}

// emailProof authorizes a provider-driven email change; nil error = allowed.
type emailProof func(ctx context.Context, email string) error

// adoptProviderEmail moves the account to the email the provider now sends
// for the same identity. It never refuses the login: when the change is not
// allowed the account keeps its email and the reason is logged.
//
// Allowed only when the new address passes proof (organization SSO: a domain
// the organization DNS-verified) and no other account holds it. Returns the
// previous email when it changed, so the caller can undo it if the save fails.
func (f federatedAccounts) adoptProviderEmail(ctx context.Context, u *userdom.User, email string, proof emailProof) (previous string, changed bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || strings.EqualFold(email, u.Email()) {
		return "", false
	}
	if proof != nil {
		if err := proof(ctx, email); err != nil {
			f.logger.Warn("identity provider email change not applied: new address not proven for this organization",
				"user_id", u.ID().String(), "reason", err.Error())
			return "", false
		}
	}
	other, err := f.users.GetByEmail(ctx, email)
	switch {
	case err == nil && other != nil && other.ID() != u.ID():
		f.logger.Warn("identity provider email change not applied: another account holds the address",
			"user_id", u.ID().String())
		return "", false
	case err != nil && !errors.Is(err, shared.ErrNotFound):
		f.logger.Warn("identity provider email change not applied: lookup failed",
			"user_id", u.ID().String(), "error", err)
		return "", false
	}
	previous = u.Email()
	if err := u.UpdateEmail(email); err != nil {
		return "", false
	}
	f.logger.Info("account email changed by the identity provider",
		"user_id", u.ID().String(), "source", "idp")
	return previous, true
}

// saveLogin persists the login (profile, email, last login). A failed save
// of an email change restores the previous email in memory so the session is
// not issued under an address the account does not hold.
func (f federatedAccounts) saveLogin(ctx context.Context, u *userdom.User, previousEmail string, emailChanged bool) {
	err := f.users.Update(ctx, u)
	if err != nil && emailChanged {
		// Most likely another account took the address meanwhile.
		_ = u.UpdateEmail(previousEmail)
		err = f.users.Update(ctx, u)
	}
	if err != nil {
		f.logger.Warn("failed to record federated login", "user_id", u.ID().String(), "error", err)
	}
}

// canonicalIssuer gives one spelling per issuer, so an identity is found
// whichever spelling the id_token used. Google signs with both
// "accounts.google.com" and "https://accounts.google.com"; social login
// records the latter.
func canonicalIssuer(iss string) string {
	if iss == "accounts.google.com" {
		return "https://accounts.google.com"
	}
	return iss
}

// entraSubject keys an Entra account on oid, the user's object id, which is
// the same for every application in the directory; sub is pairwise per
// application and changes when sign-in moves to another app registration.
// legacy is sub, the key identities were bound under before.
func entraSubject(c *oidc.Claims) (subject, legacy string) {
	if strings.TrimSpace(c.OID) != "" {
		return c.OID, c.Subject
	}
	return c.Subject, ""
}

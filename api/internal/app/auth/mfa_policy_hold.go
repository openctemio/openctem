package auth

// Who holds a person to their second factor, and how they move it to a new
// authenticator while it is required. Design: research 346 (S2);
// docs/architecture/user-two-factor-authentication.md.
//
// Turning two-factor off is refused while any organization the person belongs
// to, or the platform floor, requires it for them: otherwise a required factor
// could be off until the person's open sessions expire. The way to change
// devices without ever being unprotected is the replacement flow below: the
// old authenticator keeps working until the new one is confirmed.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/totp"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ErrMFARequiredByPolicy: two-factor cannot be turned off because an
// organization or the platform floor requires it for this person. The error
// returned is an *MFARequiredError naming who requires it.
var ErrMFARequiredByPolicy = errors.New("two-factor authentication is required for your account")

// mfaReplaceWindow is how long a replacement secret from BeginMFAReplacement
// can be confirmed.
const mfaReplaceWindow = 15 * time.Minute

// MFAPolicyHolders says who requires the person's second factor.
type MFAPolicyHolders struct {
	// Organizations whose own settings require it (everyone, administrators,
	// personal-address or privileged outside members), by name. The person is
	// a member of each, so the names are theirs to see.
	Organizations []string `json:"organizations"`
	// Platform: the platform's two-factor floor covers the person in at least
	// one organization, during its grace period too.
	Platform bool `json:"platform"`
}

// Any reports whether anybody requires the factor.
func (h MFAPolicyHolders) Any() bool { return h.Platform || len(h.Organizations) > 0 }

// MFARequiredError refuses turning two-factor off and names who requires it.
type MFARequiredError struct {
	Holders MFAPolicyHolders
}

func (e *MFARequiredError) Error() string { return ErrMFARequiredByPolicy.Error() }

// Unwrap lets errors.Is(err, ErrMFARequiredByPolicy) match.
func (e *MFARequiredError) Unwrap() error { return ErrMFARequiredByPolicy }

// mfaPolicyHolders collects who requires the user's second factor across all
// of their organizations. It fails closed: any lookup it cannot make is an
// error, and DisableMFA refuses on an error rather than guess "not required".
func (s *AuthService) mfaPolicyHolders(ctx context.Context, userID shared.ID) (MFAPolicyHolders, error) {
	h := MFAPolicyHolders{Organizations: []string{}}
	if s.tenantRepo == nil {
		return h, nil
	}
	memberships, err := s.tenantRepo.GetUserMemberships(ctx, userID)
	if err != nil {
		return h, fmt.Errorf("load memberships for 2FA policy: %w", err)
	}
	for _, um := range memberships {
		tid, err := shared.IDFromString(um.TenantID)
		if err != nil {
			return h, fmt.Errorf("membership tenant id: %w", err)
		}
		t, err := s.tenantRepo.GetByID(ctx, tid)
		if err != nil {
			return h, fmt.Errorf("load tenant for 2FA policy: %w", err)
		}
		if t == nil {
			return h, fmt.Errorf("load tenant for 2FA policy: %w", shared.ErrNotFound)
		}
		sec, err := t.SecuritySettingsStrict()
		if err != nil {
			return h, fmt.Errorf("read 2FA policy: %w", err)
		}
		req, err := s.mfaRequirementForRole(ctx, userID, tid, um.Role, sec)
		if err != nil {
			return h, err
		}
		byOrg := req.Required && req.ByOrganization
		if !byOrg {
			byOrg, err = s.memberPolicyNeedsSecondFactor(ctx, tid, userID, sec)
			if err != nil {
				return h, err
			}
		}
		switch {
		case byOrg:
			h.Organizations = append(h.Organizations, t.Name())
		case req.Required:
			h.Platform = true
		}
	}
	return h, nil
}

// memberPolicyNeedsSecondFactor applies the organization rules that depend on
// the membership itself: a personal-address member under allowed_with_mfa and
// a privileged outside member. An error means "could not tell"; callers treat
// it as required.
func (s *AuthService) memberPolicyNeedsSecondFactor(ctx context.Context, tid, userID shared.ID, sec tenantdom.SecuritySettings) (bool, error) {
	m, err := s.tenantRepo.GetMembership(ctx, userID, tid)
	if errors.Is(err, shared.ErrNotFound) {
		return false, nil // no membership: the mint refuses it elsewhere
	}
	if err != nil {
		s.logger.Warn("mfa policy: failed to load membership", "user_id", userID.String(), "tenant_id", tid.String(), "error", err)
		return true, fmt.Errorf("load membership for 2FA policy: %w", err)
	}
	if m == nil {
		return false, nil
	}
	if tenantdom.IsPersonalMember(m) && sec.PersonalAccounts.Effective() == tenantdom.PersonalAccountsAllowedWithMFA {
		return true, nil
	}
	if m.IsExternal() {
		privileged, err := s.outsideMemberPrivileged(ctx, m, tid, userID)
		if err != nil {
			return true, err
		}
		return privileged, nil
	}
	return false, nil
}

// BeginMFAReplacement starts moving the user's second factor to a new
// authenticator. It needs the current password and a code from the current
// authenticator or an unused recovery code, so a hijacked session alone cannot
// bind an attacker's device; a person who lost their phone uses a recovery
// code. The current authenticator keeps working until
// ConfirmMFAReplacement, so the account is never without a second factor.
func (s *AuthService) BeginMFAReplacement(ctx context.Context, userID, currentPassword, code string) (*MFASetup, error) {
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !isPasswordAccount(u) {
		return nil, ErrMFANotSupported
	}
	if !s.mfaEnabled() {
		return nil, ErrMFAUnavailable
	}
	if u.IsLocked() {
		return nil, ErrAccountLocked
	}
	if err := s.passwordHasher.Verify(currentPassword, *u.PasswordHash()); err != nil {
		s.recordPasswordFailure(ctx, u)
		return nil, ErrPasswordMismatch
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil || !f.Enabled {
		return nil, ErrMFANotEnabled
	}
	ok, err := s.checkTOTPOrRecovery(ctx, f, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrMFACodeInvalid
	}
	return s.newPendingSecret(ctx, u)
}

// ConfirmMFAReplacement proves the new authenticator with one of its codes,
// makes it the only one, replaces every recovery code and signs out every
// other session of the user (a session opened with the old device must not
// outlive it). The new recovery codes are returned once.
func (s *AuthService) ConfirmMFAReplacement(ctx context.Context, actx auditapp.AuditContext, userID, code string) ([]string, error) {
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !isPasswordAccount(u) {
		return nil, ErrMFANotSupported
	}
	if !s.mfaEnabled() {
		return nil, ErrMFAUnavailable
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil || !f.Enabled {
		return nil, ErrMFANotEnabled
	}
	if f.PendingSecretEncrypted == "" || f.PendingCreatedAt == nil || time.Since(*f.PendingCreatedAt) > mfaReplaceWindow {
		return nil, ErrMFANoPendingSetup
	}
	secret, err := s.mfaEncryptor.DecryptString(f.PendingSecretEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt mfa secret: %w", err)
	}
	step, ok := totp.Verify(secret, normalizeTOTPCode(code), time.Now())
	if !ok {
		return nil, ErrMFACodeInvalid
	}
	codes, hashes, err := s.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	replaced, err := s.mfaRepo.ReplaceActive(ctx, u.ID(), step, hashes)
	if err != nil {
		return nil, err
	}
	if !replaced {
		return nil, ErrMFANoPendingSetup
	}
	except, _ := shared.IDFromString(actx.SessionID)
	s.revokeUserSessions(ctx, u.ID(), except)
	s.audit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAuthMFAReplaced, auditdom.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage("Two-factor authenticator replaced; other sessions signed out").
		WithMetadata("other_sessions_ended", true))
	return codes, nil
}

// refuseMFADisableByPolicy audits and returns the refusal of turning the
// factor off while it is required.
func (s *AuthService) refuseMFADisableByPolicy(ctx context.Context, actx auditapp.AuditContext, userID shared.ID, email string, h MFAPolicyHolders) error {
	err := &MFARequiredError{Holders: h}
	s.audit(ctx, actx, auditapp.NewFailureEvent(auditdom.ActionAuthMFADisabled, auditdom.ResourceTypeUser, userID.String(), err).
		WithResourceName(email).
		WithMessage("Turning off two-factor authentication refused: required by policy").
		WithMetadata("required_by_organizations", h.Organizations).
		WithMetadata("required_by_platform", h.Platform))
	return err
}

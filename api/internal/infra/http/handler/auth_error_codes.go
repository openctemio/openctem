package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jwt"
)

// authErrorEntry is one refusal of a sign-in, SSO, SAML, social-login or
// invitation flow: the sentinel errors that cause it, the HTTP status, the
// stable code the web console translates (en and vi), and the English
// fallback text for API clients.
//
// Every refusal an end user can meet is a client error (4xx) with its own
// code. The services return sentinel errors, never sentences; the text lives
// here and in the web dictionaries. Several sentinels share one entry only
// where the answer must be identical on purpose (anti-enumeration).
type authErrorEntry struct {
	Errs    []error
	Status  int
	Code    apierror.Code
	Message string
	// Login is the `/login?error=<value>` code a redirect flow (SAML, social
	// callbacks) sends the browser to. Empty means the generic failure.
	Login string
}

// Codes of the refusals that have no constant elsewhere.
const (
	codeInvalidCredentials      apierror.Code = "INVALID_CREDENTIALS"
	codeAccountLocked           apierror.Code = "ACCOUNT_LOCKED"
	codeAccountSuspended        apierror.Code = "ACCOUNT_SUSPENDED"
	codeEmailNotVerified        apierror.Code = "EMAIL_NOT_VERIFIED"
	codeTenantCreationDisabled  apierror.Code = "ORGANIZATION_CREATION_DISABLED"
	codeAccountCannotJoinOrg    apierror.Code = "ACCOUNT_CANNOT_JOIN_ORGANIZATION"
	codeEmailAlreadyExists      apierror.Code = "EMAIL_ALREADY_EXISTS"
	codeInvalidResetToken       apierror.Code = "INVALID_RESET_TOKEN"
	codeInvalidVerifyToken      apierror.Code = "INVALID_VERIFICATION_TOKEN"
	codePasswordMismatch        apierror.Code = "PASSWORD_MISMATCH"
	codeSessionLimitReached     apierror.Code = "SESSION_LIMIT_REACHED"
	codeEmailNotAuthoritative   apierror.Code = "EMAIL_NOT_AUTHORITATIVE"
	codeAccessDenied            apierror.Code = "ORGANIZATION_ACCESS_DENIED"
	codeTenantRequired          apierror.Code = "ORGANIZATION_REQUIRED"
	codeMFAIDPEvidenceRequired  apierror.Code = "MFA_IDP_EVIDENCE_REQUIRED"
	codeMFAChallengeInvalid     apierror.Code = "MFA_CHALLENGE_INVALID"
	codeMFACodeInvalid          apierror.Code = "MFA_CODE_INVALID"
	codeMFANotSupported         apierror.Code = "MFA_NOT_SUPPORTED"
	codeMFAFederatedSession     apierror.Code = "MFA_FEDERATED_SESSION"
	codeSSOBreakGlassNeedsMFA   apierror.Code = "SSO_BREAK_GLASS_NEEDS_MFA"
	codeMFAAlreadyEnabled       apierror.Code = "MFA_ALREADY_ENABLED"
	codeMFANotEnabled           apierror.Code = "MFA_NOT_ENABLED"
	codeMFANoPendingSetup       apierror.Code = "MFA_NO_PENDING_SETUP"
	codeMFAUnavailable          apierror.Code = "MFA_UNAVAILABLE"
	codeTokenInvalid            apierror.Code = "TOKEN_INVALID"
	codeRefreshTokenInvalid     apierror.Code = "REFRESH_TOKEN_INVALID"
	codeRefreshTokenExpired     apierror.Code = "REFRESH_TOKEN_EXPIRED"
	codeRefreshTokenReused      apierror.Code = "REFRESH_TOKEN_REUSED"
	codeRefreshTokenRevoked     apierror.Code = "REFRESH_TOKEN_REVOKED"
	codeSessionExpired          apierror.Code = "SESSION_EXPIRED"
	codeSessionRevoked          apierror.Code = "SESSION_REVOKED"
	codeSessionNotFound         apierror.Code = "SESSION_NOT_FOUND"
	codeTokenFamilyMismatch     apierror.Code = "TOKEN_FAMILY_MISMATCH"
	codeSSONotConfigured        apierror.Code = "SSO_NOT_CONFIGURED"
	codeSSOProviderInactive     apierror.Code = "SSO_PROVIDER_INACTIVE"
	codeSSOInvalidState         apierror.Code = "SSO_INVALID_STATE"
	codeSSOInvalidRedirect      apierror.Code = "SSO_INVALID_REDIRECT"
	codeSSOExchangeFailed       apierror.Code = "SSO_EXCHANGE_FAILED"
	codeSSOUserInfoFailed       apierror.Code = "SSO_USERINFO_FAILED"
	codeSSOInvalidIDToken       apierror.Code = "SSO_INVALID_ID_TOKEN"
	codeSSONoEmail              apierror.Code = "SSO_NO_EMAIL"
	codeSSORegistrationDisabled apierror.Code = "SSO_REGISTRATION_DISABLED"
	codeSSODomainNotAllowed     apierror.Code = "SSO_DOMAIN_NOT_ALLOWED"
	codeSSOAwaitingApproval     apierror.Code = "SSO_AWAITING_APPROVAL"
	codeSSONotAMember           apierror.Code = "SSO_NOT_A_MEMBER"
	codeAccountLinkRequired     apierror.Code = "ACCOUNT_LINK_REQUIRED"
	codeSSODifferentMethod      apierror.Code = "SSO_DIFFERENT_METHOD"
	codeEmailUnverifiedAtIDP    apierror.Code = "EMAIL_UNVERIFIED_AT_IDP"
	codeUseAdminConsole         apierror.Code = "USE_ADMIN_CONSOLE"
	codeSAMLFailed              apierror.Code = "SAML_FAILED"
	codeOAuthDisabled           apierror.Code = "OAUTH_DISABLED"
	codeOAuthProviderDisabled   apierror.Code = "OAUTH_PROVIDER_DISABLED"
	codeOAuthInvalidProvider    apierror.Code = "OAUTH_INVALID_PROVIDER"
	codeOAuthInvalidState       apierror.Code = "OAUTH_INVALID_STATE"
	codeOAuthExchangeFailed     apierror.Code = "OAUTH_EXCHANGE_FAILED"
	codeOAuthUserInfoFailed     apierror.Code = "OAUTH_USERINFO_FAILED"
	codeOAuthAccountExists      apierror.Code = "OAUTH_ACCOUNT_EXISTS"
	codeOAuthNoEmail            apierror.Code = "OAUTH_NO_EMAIL"
	codeOAuthUseOrgSSO          apierror.Code = "OAUTH_USE_ORG_SSO"
	codeIdentityLinkedElsewhere apierror.Code = "IDENTITY_LINKED_ELSEWHERE"
	codeProviderAlreadyLinked   apierror.Code = "PROVIDER_ALREADY_LINKED"
	codeLastSignInMethod        apierror.Code = "LAST_SIGN_IN_METHOD"
	codeIdentityByOrganization  apierror.Code = "IDENTITY_MANAGED_BY_ORGANIZATION"
	codeIdentityNotFound        apierror.Code = "IDENTITY_NOT_FOUND"
	codePendingLinkInvalid      apierror.Code = "PENDING_LINK_INVALID"
	codePendingLinkNeedsSignIn  apierror.Code = "PENDING_LINK_SIGN_IN_REQUIRED"
	codeLinkProofRequired       apierror.Code = "LINK_PROOF_REQUIRED"
	codeLinkProofFailed         apierror.Code = "LINK_PROOF_FAILED"
	codeLinkProofUnavailable    apierror.Code = "LINK_PROOF_UNAVAILABLE"
	codeInvitationAlreadyMember apierror.Code = "INVITATION_ALREADY_MEMBER"
	codeInvitationSuspended     apierror.Code = "INVITATION_MEMBERSHIP_SUSPENDED"
	codeMembershipReactivate    apierror.Code = "MEMBERSHIP_SUSPENDED_REACTIVATE"
	codeInviteeNotOnVerifiedDom apierror.Code = "INVITEE_NOT_ON_VERIFIED_DOMAIN"
	codeInviteeDomainNotAllowed apierror.Code = "INVITEE_DOMAIN_NOT_ALLOWED"
	codeInvitationNoLongerValid apierror.Code = "INVITATION_NO_LONGER_VALID"
	codePersonalAccountsBlocked apierror.Code = "PERSONAL_ACCOUNTS_BLOCKED"
	codeInvitationResendTooSoon apierror.Code = "INVITATION_RESEND_TOO_SOON"
	codeInvitationsRateLimited  apierror.Code = "INVITATIONS_RATE_LIMITED"
)

func e(errs ...error) []error { return errs }

// authErrorTable lists the refusals in match order: the first entry whose
// sentinel the error wraps wins, so a specific refusal goes before a broad one.
// Handler-specific answers that need request data (password length, limit
// numbers) stay in their handlers and run before the table.
var authErrorTable = []authErrorEntry{
	// Pre-password answers are generic: a wrong email and a wrong password are
	// one entry. State refusals (locked, suspended, unverified) are raised only
	// after the password was proven, so they reveal nothing to a guesser.
	{e(auth.ErrInvalidCredentials), http.StatusUnauthorized, codeInvalidCredentials, "Invalid email or password.", ""},
	{e(auth.ErrAccountLocked), http.StatusForbidden, codeAccountLocked, "Account is locked due to too many failed attempts.", ""},
	{e(auth.ErrAccountSuspended), http.StatusForbidden, codeAccountSuspended, "Account is suspended.", "account_suspended"},
	{e(auth.ErrEmailNotVerified), http.StatusForbidden, codeEmailNotVerified, "Email is not verified.", "email_not_verified"},
	{e(auth.ErrRegistrationDisabled, auth.ErrSignupNotAvailable), http.StatusForbidden, CodeSignupNotAvailable, "Your organization isn't set up yet. Ask your administrator to invite you.", ""},
	// Sign-up with a claimed address and sign-in to an SSO-enforced
	// organization are one answer: use the organization's single sign-on.
	{e(auth.ErrSSOBreakGlassNeedsMFA), http.StatusForbidden, codeSSOBreakGlassNeedsMFA, "This organization requires SSO sign-in. Owner access with a password needs two-factor authentication: turn it on for your account and sign in again, or sign in through your identity provider.", ""},
	{e(auth.ErrSignupSSORequired, auth.ErrSSORequired), http.StatusForbidden, CodeSignupSSORequired, "Your organization requires single sign-on. Sign in through your identity provider.", "sso_required"},
	{e(auth.ErrTenantCreationDisabled), http.StatusForbidden, codeTenantCreationDisabled, "Organizations are created by the application administrator.", ""},
	{e(tenantdom.ErrBreakGlassMembership), http.StatusConflict, codeAccountCannotJoinOrg, "This account cannot be a member of an organization.", ""},
	{e(auth.ErrEmailAlreadyExists), http.StatusConflict, codeEmailAlreadyExists, "Email already exists.", ""},
	{e(auth.ErrInvalidResetToken), http.StatusBadRequest, codeInvalidResetToken, "Invalid or expired reset token.", ""},
	{e(auth.ErrInvalidVerificationToken), http.StatusBadRequest, codeInvalidVerifyToken, "Invalid or expired verification token.", ""},
	// 400, not 401: the caller IS authenticated. Clients treat a 401 as an
	// expired session and sign the user out, which is wrong for a typo.
	{e(auth.ErrPasswordMismatch), http.StatusBadRequest, codePasswordMismatch, "Current password is incorrect.", ""},
	{e(auth.ErrSessionLimitReached), http.StatusForbidden, codeSessionLimitReached, "Maximum number of active sessions reached.", ""},
	{e(tenantdom.ErrOrganizationSuspended), http.StatusForbidden, apierror.Code(tenantdom.CodeOrganizationSuspended), tenantdom.MessageOrganizationSuspended, "organization_unavailable"},
	// A missing organization, a non-member and a removed membership answer
	// alike: nothing says whether the organization exists.
	{e(auth.ErrTenantAccessDenied), http.StatusForbidden, codeAccessDenied, "You do not have access to this organization.", ""},
	{e(auth.ErrTenantRequired), http.StatusBadRequest, codeTenantRequired, "An organization is required.", ""},

	// Two-factor authentication.
	{e(auth.ErrMFAChallengeInvalid), http.StatusUnauthorized, codeMFAChallengeInvalid, "Your sign-in verification expired or is no longer valid. Sign in again.", ""},
	{e(auth.ErrMFACodeInvalid), http.StatusUnauthorized, codeMFACodeInvalid, "Invalid verification code.", ""},
	{e(auth.ErrSSOMFAEvidenceRequired), http.StatusForbidden, codeMFAIDPEvidenceRequired, "This organization requires your identity provider to confirm a second factor. Sign in again through your identity provider with multi-factor authentication.", ""},
	{e(auth.ErrMFAEnrollmentRequired), http.StatusForbidden, apierror.CodeMFAEnrollmentRequired, "This organization requires two-factor authentication. Sign in again to complete it.", ""},
	{e(auth.ErrMFANotSupported), http.StatusBadRequest, codeMFANotSupported, "Two-factor authentication for this account is managed by your identity provider.", ""},
	{e(auth.ErrReauthRequired), http.StatusForbidden, apierror.CodeReauthRequired, "For your security, sign in again to set up two-factor authentication.", ""},
	{e(auth.ErrMFAFederatedSession), http.StatusBadRequest, codeMFAFederatedSession, "This session was started through an identity provider; sign in with your password to set up two-factor authentication.", ""},
	{e(auth.ErrMFAAlreadyEnabled), http.StatusConflict, codeMFAAlreadyEnabled, "Two-factor authentication is already enabled.", ""},
	{e(auth.ErrMFANotEnabled), http.StatusBadRequest, codeMFANotEnabled, "Two-factor authentication is not enabled.", ""},
	{e(auth.ErrMFANoPendingSetup), http.StatusBadRequest, codeMFANoPendingSetup, "Start two-factor setup first.", ""},
	{e(auth.ErrMFAUnavailable), http.StatusServiceUnavailable, codeMFAUnavailable, "Two-factor authentication is not available on this server.", ""},

	// Sessions and tokens. A malformed, forged or expired refresh JWT (or any
	// other token presented as one) is a 401, not a server error.
	{e(jwt.ErrInvalidToken, jwt.ErrExpiredToken, jwt.ErrInvalidTokenType), http.StatusUnauthorized, codeTokenInvalid, "Invalid or expired token.", ""},
	{e(session.ErrRefreshTokenNotFound), http.StatusUnauthorized, codeRefreshTokenInvalid, "Invalid or expired refresh token.", ""},
	{e(session.ErrRefreshTokenExpired), http.StatusUnauthorized, codeRefreshTokenExpired, "Refresh token has expired.", ""},
	{e(session.ErrRefreshTokenUsed), http.StatusUnauthorized, codeRefreshTokenReused, "Refresh token has already been used.", ""},
	{e(session.ErrRefreshTokenRevoked), http.StatusUnauthorized, codeRefreshTokenRevoked, "Refresh token has been revoked.", ""},
	{e(session.ErrSessionExpired), http.StatusUnauthorized, codeSessionExpired, "Session has expired. Sign in again.", ""},
	{e(session.ErrSessionRevoked), http.StatusUnauthorized, codeSessionRevoked, "Session has been revoked.", ""},
	// Unknown session id, or one that belongs to another user: identical, so a
	// caller cannot probe others' ids.
	{e(session.ErrSessionNotFound), http.StatusNotFound, codeSessionNotFound, "Session not found.", ""},
	{e(session.ErrTokenFamilyMismatch), http.StatusUnauthorized, codeTokenFamilyMismatch, "Invalid token.", ""},

	// Organization SSO. An unknown organization answers exactly like one
	// without that provider.
	{e(auth.ErrSSOTenantNotFound, auth.ErrSSONoActiveProviders, auth.ErrSSOProviderNotFound), http.StatusNotFound, codeSSONotConfigured, "SSO provider not configured.", ""},
	{e(auth.ErrSSOProviderInactive), http.StatusBadRequest, codeSSOProviderInactive, "SSO provider is not active.", ""},
	{e(auth.ErrSSOInvalidState), http.StatusBadRequest, codeSSOInvalidState, "Invalid or expired state token.", ""},
	{e(auth.ErrSSOInvalidRedirectURI), http.StatusBadRequest, codeSSOInvalidRedirect, "Invalid redirect URI.", ""},
	{e(auth.ErrSSOExchangeFailed), http.StatusBadRequest, codeSSOExchangeFailed, "Failed to complete SSO authentication.", ""},
	{e(auth.ErrSSOUserInfoFailed), http.StatusBadRequest, codeSSOUserInfoFailed, "Failed to retrieve user information.", ""},
	{e(auth.ErrSSOInvalidIDToken), http.StatusUnauthorized, codeSSOInvalidIDToken, "The identity provider's response could not be verified.", ""},
	{e(auth.ErrSSONoEmail), http.StatusBadRequest, codeSSONoEmail, "The identity provider did not return an email address.", ""},
	{e(auth.ErrSSORegistrationDisabled), http.StatusForbidden, codeSSORegistrationDisabled, "Registration is disabled.", ""},
	// Refusals after the provider authenticated the person. Each says only
	// what the person can do; none says whether another organization exists.
	{e(auth.ErrEmailUnverifiedAtIDP), http.StatusForbidden, codeEmailUnverifiedAtIDP, "Your identity provider did not verify your email address.", "email_unverified_at_idp"},
	{e(auth.ErrUseAdminConsole), http.StatusForbidden, codeUseAdminConsole, "This account signs in on the admin console.", "use_console"},
	{e(auth.ErrSSODifferentMethod), http.StatusForbidden, codeSSODifferentMethod, "This email is registered with a different sign-in method. Use the method you signed up with.", "different_method"},
	{e(auth.ErrSSODomainNotAllowed, auth.ErrSSOFederatedDomainUnverified), http.StatusForbidden, codeSSODomainNotAllowed, "Your email domain is not allowed for this organization.", "domain_not_allowed"},
	{e(auth.ErrSSOAwaitingApproval), http.StatusForbidden, codeSSOAwaitingApproval, "Your access to this organization is waiting for an administrator's approval.", "awaiting_approval"},
	{e(auth.ErrSSONotAMember, auth.ErrSSOFederatedNotMember), http.StatusForbidden, codeSSONotAMember, "You do not have access to this organization. Contact your administrator.", "not_member"},
	{e(auth.ErrEmailNotAuthoritative), http.StatusForbidden, codeEmailNotAuthoritative, "This provider cannot prove that you own this email address. Sign in with your password, or ask an administrator, and link the provider afterwards.", "link_required"},
	{e(auth.ErrAccountLinkRequiresVerification, auth.ErrSSOFederatedTakeover), http.StatusForbidden, codeAccountLinkRequired, "An account with this email already exists. Sign in with your existing credentials first, then link this identity provider.", "link_required"},

	// Social sign-in.
	{e(auth.ErrOAuthDisabled), http.StatusForbidden, codeOAuthDisabled, "OAuth is disabled.", ""},
	{e(auth.ErrProviderDisabled), http.StatusForbidden, codeOAuthProviderDisabled, "This OAuth provider is not configured.", ""},
	{e(auth.ErrInvalidProvider), http.StatusBadRequest, codeOAuthInvalidProvider, "Invalid OAuth provider.", "invalid_provider"},
	{e(auth.ErrInvalidState), http.StatusBadRequest, codeOAuthInvalidState, "Invalid or expired state token.", ""},
	{e(auth.ErrOAuthExchangeFailed), http.StatusBadRequest, codeOAuthExchangeFailed, "Failed to exchange authorization code.", ""},
	{e(auth.ErrOAuthUserInfoFailed), http.StatusBadRequest, codeOAuthUserInfoFailed, "Failed to get user information from the provider.", ""},
	{e(auth.ErrOAuthNoEmail), http.StatusBadRequest, codeOAuthNoEmail, "The provider did not return an email address.", ""},
	// The address names an account that signs in another way and this
	// provider identity is not linked to it. The provider verified the
	// address, so saying the account exists tells the person nothing they
	// could not learn by signing in with it.
	{e(auth.ErrOAuthAccountExists), http.StatusConflict, codeOAuthAccountExists, "An account with this email already exists. Sign in with your password or the method you used before to link this provider.", "account_exists"},

	// The provider identity is managed by the organization's single sign-on:
	// the social button never signs it in (nothing written, no session).
	{e(auth.ErrOAuthUseOrgSSO), http.StatusConflict, codeOAuthUseOrgSSO, "This account signs in through your organization. Use your organization's sign-in.", "use_org_sso"},

	// Linked sign-in methods (Account > Security). The caller owns the
	// provider account, so saying it is linked elsewhere tells them nothing
	// they could not learn by signing in with it.
	{e(auth.ErrIdentityLinkedElsewhere), http.StatusConflict, codeIdentityLinkedElsewhere, "This provider account is already linked to another account.", ""},
	{e(auth.ErrProviderAlreadyLinked), http.StatusConflict, codeProviderAlreadyLinked, "Another account of this provider is already linked. Unlink it first.", ""},
	{e(auth.ErrLastSignInMethod), http.StatusConflict, codeLastSignInMethod, "This is your only way to sign in, so it cannot be removed.", ""},
	{e(auth.ErrIdentityNotUnlinkable), http.StatusConflict, codeIdentityByOrganization, "This sign-in method is managed by your organization.", ""},
	{e(auth.ErrIdentityNotFound), http.StatusNotFound, codeIdentityNotFound, "Sign-in method not found.", ""},
	{e(auth.ErrPendingLinkInvalid), http.StatusNotFound, codePendingLinkInvalid, "There is no sign-in method waiting to be linked to this account. Sign in with it again, or link it in Account > Security.", ""},
	{e(auth.ErrPendingLinkNeedsSignIn), http.StatusForbidden, codePendingLinkNeedsSignIn, "Sign in to your account again to link this sign-in method.", ""},
	// The proof typed to link or unlink (auth/link_proof.go). A wrong code
	// or password also counts towards the account lockout.
	{e(auth.ErrLinkProofRequired), http.StatusForbidden, codeLinkProofRequired, "Enter the code from your authenticator app, or your password if two-factor authentication is off, to change sign-in methods.", ""},
	{e(auth.ErrLinkProofFailed), http.StatusForbidden, codeLinkProofFailed, "The code or password is not correct.", ""},
	{e(auth.ErrLinkProofUnavailable), http.StatusForbidden, codeLinkProofUnavailable, "Turn on two-factor authentication before you change sign-in methods.", ""},

	// Invitations.
	{e(tenantapp.ErrInvitationAlreadyMember), http.StatusBadRequest, codeInvitationAlreadyMember, "This person is already a member of this organization.", ""},
	{e(tenantapp.ErrInvitationMembershipSuspended), http.StatusBadRequest, codeInvitationSuspended, "Your access to this organization is suspended. Contact an administrator to be reactivated.", ""},
	{e(tenantapp.ErrMembershipSuspendedReactivate), http.StatusBadRequest, codeMembershipReactivate, "This person's membership is suspended. Reactivate it in Members instead.", ""},
	{e(tenantapp.ErrInviteeNotOnVerifiedDomain), http.StatusForbidden, codeInviteeNotOnVerifiedDom, "This address is not on a domain verified for the organization.", ""},
	{e(tenantapp.ErrEmailDomainNotAllowed), http.StatusBadRequest, codeInviteeDomainNotAllowed, "This email domain is not allowed for the organization.", ""},
	{e(tenantapp.ErrInvitationNoLongerValid), http.StatusForbidden, codeInvitationNoLongerValid, "This invitation is no longer valid. Ask the organization for a new one.", ""},
	{e(tenantapp.ErrPersonalAccountsBlocked), http.StatusForbidden, codePersonalAccountsBlocked, "This organization does not accept personal email accounts.", ""},
	{e(tenantdom.ErrInvitationResendTooSoon), http.StatusTooManyRequests, codeInvitationResendTooSoon, "This invitation was sent a moment ago. Try again shortly.", ""},
	{e(tenantdom.ErrInvitationRateLimited), http.StatusTooManyRequests, codeInvitationsRateLimited, "Too many invitations were sent. Try again later.", ""},
}

// lookupAuthError returns the table entry for err.
func lookupAuthError(err error) (authErrorEntry, bool) {
	if err == nil {
		return authErrorEntry{}, false
	}
	for _, en := range authErrorTable {
		for _, target := range en.Errs {
			if errors.Is(err, target) {
				return en, true
			}
		}
	}
	return authErrorEntry{}, false
}

// writeAuthTableError writes the coded answer for err and reports whether the
// table knew it.
func writeAuthTableError(w http.ResponseWriter, err error) bool {
	en, ok := lookupAuthError(err)
	if !ok {
		return false
	}
	apierror.New(en.Status, en.Code, en.Message).WriteJSON(w)
	return true
}

// samlLoginErrorCode is the `/login?error=` value for a failed federated
// sign-in redirect: the entry's login code, else the generic SAML failure.
func samlLoginErrorCode(err error) string {
	if en, ok := lookupAuthError(err); ok && en.Login != "" {
		return en.Login
	}
	return strings.ToLower(string(codeSAMLFailed))
}

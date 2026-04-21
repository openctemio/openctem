package app

// Compatibility shim — real impl lives in internal/app/auth/.
// Covers auth, sso, oauth, session, email, ws-ticket services plus
// tenant-scoped SMTP + storage resolvers (auth bounded context).

import "github.com/openctemio/api/internal/app/auth"

type (
	AuthService             = auth.AuthService
	SSOService              = auth.SSOService
	OAuthService            = auth.OAuthService
	SessionService          = auth.SessionService
	EmailService            = auth.EmailService
	WSTicketService         = auth.WSTicketService
	IntegrationSMTPResolver = auth.IntegrationSMTPResolver
	TenantSMTPResolver      = auth.TenantSMTPResolver
	SettingsStorageResolver = auth.SettingsStorageResolver

	WSTicketClaims           = auth.WSTicketClaims
	WSTicketStore            = auth.WSTicketStore
	SMTPAvailabilityCheck    = auth.SMTPAvailabilityCheck
	TenantMemberCreator      = auth.TenantMemberCreator
	TenantMembershipInfo     = auth.TenantMembershipInfo
	TenantMembershipProvider = auth.TenantMembershipProvider

	// Input/result DTOs.
	AcceptInvitationWithRefreshTokenInput  = auth.AcceptInvitationWithRefreshTokenInput
	AcceptInvitationWithRefreshTokenResult = auth.AcceptInvitationWithRefreshTokenResult
	AuthorizationURLInput                  = auth.AuthorizationURLInput
	AuthorizationURLResult                 = auth.AuthorizationURLResult
	CallbackInput                          = auth.CallbackInput
	CallbackResult                         = auth.CallbackResult
	ChangePasswordInput                    = auth.ChangePasswordInput
	CreateFirstTeamInput                   = auth.CreateFirstTeamInput
	CreateFirstTeamResult                  = auth.CreateFirstTeamResult
	CreateProviderInput                    = auth.CreateProviderInput
	ExchangeTokenInput                     = auth.ExchangeTokenInput
	ExchangeTokenResult                    = auth.ExchangeTokenResult
	ForgotPasswordInput                    = auth.ForgotPasswordInput
	ForgotPasswordResult                   = auth.ForgotPasswordResult
	LoginInput                             = auth.LoginInput
	LoginResult                            = auth.LoginResult
	OAuthProvider                          = auth.OAuthProvider
	OAuthUserInfo                          = auth.OAuthUserInfo
	ProviderInfo                           = auth.ProviderInfo
	RefreshTokenInput                      = auth.RefreshTokenInput
	RefreshTokenResult                     = auth.RefreshTokenResult
	RegisterInput                          = auth.RegisterInput
	RegisterResult                         = auth.RegisterResult
	ResetPasswordInput                     = auth.ResetPasswordInput
	SessionInfo                            = auth.SessionInfo
	SessionResult                          = auth.SessionResult
	SSOAuthorizeInput                      = auth.SSOAuthorizeInput
	SSOAuthorizeResult                     = auth.SSOAuthorizeResult
	SSOCallbackInput                       = auth.SSOCallbackInput
	SSOCallbackResult                      = auth.SSOCallbackResult
	SSOProviderInfo                        = auth.SSOProviderInfo
	SSOUserInfo                            = auth.SSOUserInfo
	UpdateProviderInput                    = auth.UpdateProviderInput
)

var (
	NewAuthService                = auth.NewAuthService
	NewSSOService                 = auth.NewSSOService
	NewOAuthService               = auth.NewOAuthService
	NewSessionService             = auth.NewSessionService
	NewEmailService               = auth.NewEmailService
	NewWSTicketService            = auth.NewWSTicketService
	NewIntegrationSMTPResolver    = auth.NewIntegrationSMTPResolver
	NewSettingsStorageResolver    = auth.NewSettingsStorageResolver
	SMTPConfigFromIntegrationMeta = auth.SMTPConfigFromIntegrationMeta

	// Sentinel errors.
	ErrTicketNotFound           = auth.ErrTicketNotFound
	ErrAccountLocked            = auth.ErrAccountLocked
	ErrAccountSuspended         = auth.ErrAccountSuspended
	ErrEmailAlreadyExists       = auth.ErrEmailAlreadyExists
	ErrEmailNotVerified         = auth.ErrEmailNotVerified
	ErrInvalidCredentials       = auth.ErrInvalidCredentials
	ErrInvalidProvider          = auth.ErrInvalidProvider
	ErrInvalidResetToken        = auth.ErrInvalidResetToken
	ErrInvalidState             = auth.ErrInvalidState
	ErrInvalidVerificationToken = auth.ErrInvalidVerificationToken
	ErrOAuthDisabled            = auth.ErrOAuthDisabled
	ErrOAuthExchangeFailed      = auth.ErrOAuthExchangeFailed
	ErrOAuthUserInfoFailed      = auth.ErrOAuthUserInfoFailed
	ErrPasswordMismatch         = auth.ErrPasswordMismatch
	ErrProviderDisabled         = auth.ErrProviderDisabled
	ErrRegistrationDisabled     = auth.ErrRegistrationDisabled
	ErrSessionLimitReached      = auth.ErrSessionLimitReached
	ErrSSODecryptionFailed      = auth.ErrSSODecryptionFailed
	ErrSSODomainNotAllowed      = auth.ErrSSODomainNotAllowed
	ErrSSOExchangeFailed        = auth.ErrSSOExchangeFailed
	ErrSSOInvalidDefaultRole    = auth.ErrSSOInvalidDefaultRole
	ErrSSOInvalidRedirectURI    = auth.ErrSSOInvalidRedirectURI
	ErrSSOInvalidState          = auth.ErrSSOInvalidState
	ErrSSONoActiveProviders     = auth.ErrSSONoActiveProviders
	ErrSSONoEmail               = auth.ErrSSONoEmail
	ErrSSOProviderInactive      = auth.ErrSSOProviderInactive
	ErrSSOProviderNotFound      = auth.ErrSSOProviderNotFound
	ErrSSOProviderUnsupported   = auth.ErrSSOProviderUnsupported
	ErrSSOTenantNotFound        = auth.ErrSSOTenantNotFound
	ErrSSOUserInfoFailed        = auth.ErrSSOUserInfoFailed
	ErrTenantAccessDenied       = auth.ErrTenantAccessDenied
	ErrTenantRequired           = auth.ErrTenantRequired
)

// OAuth provider constants.
const (
	OAuthProviderGoogle    = auth.OAuthProviderGoogle
	OAuthProviderGitHub    = auth.OAuthProviderGitHub
	OAuthProviderMicrosoft = auth.OAuthProviderMicrosoft
)

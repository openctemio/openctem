package auth

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	emaildom "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TenantSMTPResolver resolves per-tenant SMTP configuration from integrations.
// Returns nil if tenant has no custom SMTP config (fallback to system default).
type TenantSMTPResolver interface {
	GetTenantSMTPConfig(ctx context.Context, tenantID string) (*emaildom.Config, error)
}

// EmailService handles sending emails for various application events.
// Supports per-tenant SMTP via TenantSMTPResolver: if a tenant has a custom
// email integration configured, it uses that SMTP server instead of the system default.
type EmailService struct {
	sender     emaildom.Sender // System-wide default sender
	tenantSMTP TenantSMTPResolver
	config     config.SMTPConfig
	appName    string
	branding   emaildom.Branding
	locales    EmailLocaleResolver
	logger     *logger.Logger
}

// SetBranding sets the brand's email footer line and "Powered by" credit,
// added to every email this service sends.
func (s *EmailService) SetBranding(b emaildom.Branding) {
	s.branding = b
}

// NewEmailService creates a new EmailService.
func NewEmailService(sender emaildom.Sender, cfg config.SMTPConfig, appName string, log *logger.Logger) *EmailService {
	return &EmailService{
		sender:  sender,
		config:  cfg,
		appName: appName,
		logger:  log.With("service", "email"),
	}
}

// SetTenantSMTPResolver sets the per-tenant SMTP resolver.
func (s *EmailService) SetTenantSMTPResolver(resolver TenantSMTPResolver) {
	s.tenantSMTP = resolver
}

// SendReport emails an already-rendered HTML report (organization content)
// to explicit recipients. With a tenantID it goes through the organization's
// own relay when one is active; if the organization chose a relay that cannot
// be used now, the report is NOT sent through the platform relay (the
// organization may have chosen its relay for data-handling reasons): the
// error is returned. Without an organization relay (mode off, none set) and
// with an empty tenantID it uses the platform relay. No-op (returns nil) when
// there are no recipients; errors if no SMTP sender is configured.
func (s *EmailService) SendReport(ctx context.Context, tenantID string, to []string, subject, htmlBody string) error {
	if len(to) == 0 {
		return nil
	}
	sender, err := s.contentSender(ctx, tenantID)
	if err != nil {
		return err
	}
	if sender == nil || !sender.IsConfigured() {
		return fmt.Errorf("email: no SMTP sender configured")
	}
	return sender.Send(ctx, &emaildom.Message{
		To:      to,
		Subject: subject,
		Body:    htmlBody + string(s.branding.FooterHTML()),
		IsHTML:  true,
	})
}

// contentSender is the sender of organization content mail (reports): the
// organization relay when active, the platform relay when the organization
// has none, and an error (never the platform relay) when its relay is
// active but unusable.
func (s *EmailService) contentSender(ctx context.Context, tenantID string) (emaildom.Sender, error) {
	if s.tenantSMTP == nil || tenantID == "" {
		return s.sender, nil
	}
	cfg, err := s.tenantSMTP.GetTenantSMTPConfig(ctx, tenantID)
	if err != nil {
		s.logger.Warn("organization mail relay unusable; content mail not sent", "tenant_id", logSafe(tenantID), "error", err)
		return nil, err
	}
	if cfg == nil {
		return s.sender, nil
	}
	return emaildom.NewSMTPSender(*cfg), nil
}

// getSenderForTenant is the sender of organization business mail with no
// credentials and no exposure data (invitation notice, member suspended or
// reactivated): the organization relay when active, else the platform relay,
// including when the organization's relay cannot be used now. It is never used
// for mail that carries a credential or proves control of an account (account
// setup and set-password links, password reset, owner recovery, first owner,
// e-mail verification, two-factor): that mail uses the platform relay only
// (platformSender).
func (s *EmailService) getSenderForTenant(ctx context.Context, tenantID string) emaildom.Sender {
	if s.tenantSMTP == nil || tenantID == "" {
		return s.sender
	}

	cfg, err := s.tenantSMTP.GetTenantSMTPConfig(ctx, tenantID)
	if err != nil {
		s.logger.Warn("organization mail relay unusable; using the platform relay", "tenant_id", logSafe(tenantID), "error", err)
		return s.sender
	}
	if cfg == nil {
		return s.sender
	}

	return emaildom.NewSMTPSender(*cfg)
}

// IsConfigured returns true if email service is properly configured.
func (s *EmailService) IsConfigured() bool {
	return s.sender != nil && s.sender.IsConfigured()
}

// HasSystemSMTP implements SMTPAvailabilityCheck.
// Returns true if the system-wide SMTP sender is configured.
func (s *EmailService) HasSystemSMTP() bool {
	return s.IsConfigured()
}

// HasTenantSMTP implements SMTPAvailabilityCheck. It is always false:
// verification, password reset and the other account security mail are
// sent through the platform relay only (an organization's relay is
// organization-controlled infrastructure and must never carry another
// organization's member's account mail), so an organization relay does not
// make account verification possible.
func (s *EmailService) HasTenantSMTP(_ context.Context, _ string) bool {
	return false
}

// SendVerificationEmail sends an email verification link to a user.
func (s *EmailService) SendVerificationEmail(ctx context.Context, userEmail, userName, token string, expiresIn time.Duration) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping verification email",
			"email", logSafe(userEmail),
		)
		return nil
	}

	// The token goes in the URL fragment (as for invitations): the browser
	// never sends it to a server. The web app's /verify-email page reads it.
	verificationURL := fmt.Sprintf("%s/verify-email#token=%s", strings.TrimSuffix(s.config.BaseURL, "/"), url.QueryEscape(token))

	loc := s.localeForEmail(ctx, userEmail, "")
	data := emaildom.VerifyEmailData{
		Lang:            emaildom.Lang{Locale: loc},
		UserName:        userName,
		Email:           userEmail,
		VerificationURL: verificationURL,
		ExpiresIn:       emaildom.FormatDuration(loc, expiresIn),
		AppName:         s.appName,
		Branding:        s.branding,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, emaildom.TemplateVerifyEmail, data); err != nil {
		s.logger.Error("failed to send verification email",
			"email", logSafe(userEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	s.logger.Info("verification email sent",
		"email", logSafe(userEmail),
	)
	return nil
}

// SendPasswordResetEmail sends a password reset link to a user.
func (s *EmailService) SendPasswordResetEmail(ctx context.Context, userEmail, userName, token string, expiresIn time.Duration, ipAddress string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping password reset email",
			"email", logSafe(userEmail),
		)
		return nil
	}

	// The token goes in the URL fragment, as for verification and invitation
	// links: the browser never sends it to a server, so it stays out of access
	// logs and Referer headers.
	resetURL := fmt.Sprintf("%s/reset-password#token=%s", strings.TrimSuffix(s.config.BaseURL, "/"), url.QueryEscape(token))

	loc := s.localeForEmail(ctx, userEmail, "")
	data := emaildom.PasswordResetData{
		Lang:        emaildom.Lang{Locale: loc},
		UserName:    userName,
		Email:       userEmail,
		ResetURL:    resetURL,
		ExpiresIn:   emaildom.FormatDuration(loc, expiresIn),
		AppName:     s.appName,
		Branding:    s.branding,
		IPAddress:   ipAddress,
		RequestedAt: emaildom.FormatTime(loc, time.Now()),
	}

	if err := s.sender.SendTemplate(ctx, userEmail, emaildom.TemplatePasswordReset, data); err != nil {
		s.logger.Error("failed to send password reset email",
			"email", logSafe(userEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	s.logger.Info("password reset email sent",
		"email", logSafe(userEmail),
	)
	return nil
}

// SendPasswordChangedEmail sends a notification that the password was changed.
func (s *EmailService) SendPasswordChangedEmail(ctx context.Context, userEmail, userName, ipAddress string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping password changed email",
			"email", logSafe(userEmail),
		)
		return nil
	}

	loc := s.localeForEmail(ctx, userEmail, "")
	data := emaildom.PasswordChangedData{
		Lang:      emaildom.Lang{Locale: loc},
		UserName:  userName,
		Email:     userEmail,
		ChangedAt: emaildom.FormatTime(loc, time.Now()),
		IPAddress: ipAddress,
		AppName:   s.appName,
		Branding:  s.branding,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, emaildom.TemplatePasswordChanged, data); err != nil {
		s.logger.Error("failed to send password changed email",
			"email", logSafe(userEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send password changed email: %w", err)
	}

	s.logger.Info("password changed email sent",
		"email", logSafe(userEmail),
	)
	return nil
}

// SendWelcomeEmail sends a welcome email to a new user.
func (s *EmailService) SendWelcomeEmail(ctx context.Context, userEmail, userName string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping welcome email",
			"email", logSafe(userEmail),
		)
		return nil
	}

	loginURL := fmt.Sprintf("%s/login", strings.TrimSuffix(s.config.BaseURL, "/"))

	data := emaildom.WelcomeData{
		Lang:     emaildom.Lang{Locale: s.localeForEmail(ctx, userEmail, "")},
		UserName: userName,
		Email:    userEmail,
		LoginURL: loginURL,
		AppName:  s.appName,
		Branding: s.branding,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, emaildom.TemplateWelcome, data); err != nil {
		s.logger.Error("failed to send welcome email",
			"email", logSafe(userEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	s.logger.Info("welcome email sent",
		"email", logSafe(userEmail),
	)
	return nil
}

// SendMemberSuspendedEmail notifies a user that their tenant
// access has been suspended. Uses per-tenant SMTP if configured.
// Best-effort: returns nil and logs a warning if email is not
// configured for the tenant — the suspend operation should succeed
// even when the user can't be notified.
func (s *EmailService) SendMemberSuspendedEmail(
	ctx context.Context,
	recipientEmail, recipientName, teamName, actorName, tenantID string,
) error {
	sender := s.sender
	if tenantID != "" {
		sender = s.getSenderForTenant(ctx, tenantID)
	}
	if sender == nil || !sender.IsConfigured() {
		s.logger.Warn("email service not configured, skipping member suspended email",
			"email", logSafe(recipientEmail), "tenant_id", logSafe(tenantID))
		return nil
	}

	data := emaildom.MemberStatusChangeData{
		Lang:      emaildom.Lang{Locale: s.localeForEmail(ctx, recipientEmail, tenantID)},
		UserName:  recipientName,
		TeamName:  teamName,
		ActorName: actorName,
		AppURL:    s.config.BaseURL,
		AppName:   s.appName,
		Branding:  s.branding,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateMemberSuspended, data); err != nil {
		s.logger.Error("failed to send member suspended email",
			"email", logSafe(recipientEmail), "error", err)
		return fmt.Errorf("failed to send member suspended email: %w", err)
	}

	s.logger.Info("member suspended email sent",
		"email", logSafe(recipientEmail), "team", logSafe(teamName))
	return nil
}

// SendMemberReactivatedEmail notifies a user that their access
// has been restored. Same best-effort semantics as
// SendMemberSuspendedEmail.
func (s *EmailService) SendMemberReactivatedEmail(
	ctx context.Context,
	recipientEmail, recipientName, teamName, actorName, tenantID string,
) error {
	sender := s.sender
	if tenantID != "" {
		sender = s.getSenderForTenant(ctx, tenantID)
	}
	if sender == nil || !sender.IsConfigured() {
		s.logger.Warn("email service not configured, skipping member reactivated email",
			"email", logSafe(recipientEmail), "tenant_id", logSafe(tenantID))
		return nil
	}

	data := emaildom.MemberStatusChangeData{
		Lang:      emaildom.Lang{Locale: s.localeForEmail(ctx, recipientEmail, tenantID)},
		UserName:  recipientName,
		TeamName:  teamName,
		ActorName: actorName,
		AppURL:    s.config.BaseURL,
		AppName:   s.appName,
		Branding:  s.branding,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateMemberReactivated, data); err != nil {
		s.logger.Error("failed to send member reactivated email",
			"email", logSafe(recipientEmail), "error", err)
		return fmt.Errorf("failed to send member reactivated email: %w", err)
	}

	s.logger.Info("member reactivated email sent",
		"email", logSafe(recipientEmail), "team", logSafe(teamName))
	return nil
}

// platformSender is the sender of account security mail: the platform relay,
// whatever organization the mail is about. An organization relay is
// organization-controlled infrastructure; it never sees a set-password link,
// a reset link or a verification code.
func (s *EmailService) platformSender() emaildom.Sender {
	return s.sender
}

// CanDeliverTo reports whether account security mail (set-password links) can
// be sent for tenantID: only the platform relay carries it, so this is true
// when the platform relay is configured, whatever the organization's own relay.
func (s *EmailService) CanDeliverTo(_ context.Context, _ string) bool {
	sender := s.platformSender()
	return sender != nil && sender.IsConfigured()
}

// AccountSetupURL is the UI page that consumes a one-time set-password token.
func (s *EmailService) AccountSetupURL(token string) string {
	return fmt.Sprintf("%s/set-password#token=%s", strings.TrimSuffix(s.config.BaseURL, "/"), url.QueryEscape(token))
}

// SendAccountSetupEmail sends the one-time set-password link for an account an
// administrator created. Unlike the best-effort notifications it returns an
// error when no sender is configured, so the caller can fall back to showing
// the link to the administrator instead of silently dropping it. The link is
// a credential: it goes through the platform relay only, never an
// organization relay (tenantID is only for the log line).
func (s *EmailService) SendAccountSetupEmail(ctx context.Context, tenantID, recipientEmail, recipientName, teamName, token string, expiresIn time.Duration) error {
	sender := s.platformSender()
	if sender == nil || !sender.IsConfigured() {
		return fmt.Errorf("email: no SMTP sender configured")
	}
	loc := s.localeForEmail(ctx, recipientEmail, tenantID)
	data := emaildom.AccountSetupData{
		Lang:      emaildom.Lang{Locale: loc},
		UserName:  recipientName,
		TeamName:  teamName,
		SetupURL:  s.AccountSetupURL(token),
		ExpiresIn: emaildom.FormatDuration(loc, expiresIn),
		AppName:   s.appName,
		Branding:  s.branding,
	}
	// tenantID reaches here from the request path; strip line breaks before
	// logging it (CWE-117).
	logTenant := logSafe(tenantID)
	if err := sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateAccountSetup, data); err != nil {
		s.logger.Error("failed to send account setup email", "tenant_id", logTenant)
		return fmt.Errorf("failed to send account setup email: %w", err)
	}
	s.logger.Info("account setup email sent", "tenant_id", logTenant)
	return nil
}

// CanDeliverSystem reports whether the system SMTP sender can send mail.
func (s *EmailService) CanDeliverSystem() bool { return s.IsConfigured() }

// SendAdminInvitationEmail sends a new platform administrator the one-time
// link where they choose their password. It uses the system sender only and
// returns an error when none is configured or the send fails, so the caller
// never reports an invitation that was not sent.
func (s *EmailService) SendAdminInvitationEmail(ctx context.Context, recipientEmail, recipientName, token string, expiresIn time.Duration) error {
	if !s.IsConfigured() {
		return fmt.Errorf("email: no SMTP sender configured")
	}
	loc := s.localeForEmail(ctx, recipientEmail, "")
	data := emaildom.AccountSetupData{
		Lang:      emaildom.Lang{Locale: loc},
		UserName:  recipientName,
		TeamName:  emaildom.Text(loc, "setup.scopePlatformAdmin"),
		SetupURL:  s.AccountSetupURL(token),
		ExpiresIn: emaildom.FormatDuration(loc, expiresIn),
		AppName:   s.appName,
		Branding:  s.branding,
	}
	if err := s.sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateAccountSetup, data); err != nil {
		s.logger.Error("failed to send administrator invitation email")
		return fmt.Errorf("failed to send administrator invitation email: %w", err)
	}
	s.logger.Info("administrator invitation email sent")
	return nil
}

// SendTeamInvitationEmail sends a team invitation email.
// Uses per-tenant SMTP if configured, otherwise falls back to system SMTP.
func (s *EmailService) SendTeamInvitationEmail(ctx context.Context, recipientEmail, inviterName, teamName, token string, expiresIn time.Duration, tenantID ...string) error {
	// Resolve sender: per-tenant or system default
	sender := s.sender
	if len(tenantID) > 0 && tenantID[0] != "" {
		sender = s.getSenderForTenant(ctx, tenantID[0])
	}

	if sender == nil || !sender.IsConfigured() {
		s.logger.Warn("email service not configured, skipping team invitation email",
			"email", logSafe(recipientEmail),
		)
		return nil
	}

	// The token goes in the URL fragment, which the browser never sends to a
	// server: it stays out of access logs, proxies and Referer headers
	// (RFC-041). The web app reads it from the fragment and removes it.
	invitationURL := fmt.Sprintf("%s/invitations#token=%s", s.config.BaseURL, url.QueryEscape(token))

	tenant := ""
	if len(tenantID) > 0 {
		tenant = tenantID[0]
	}
	loc := s.localeForEmail(ctx, recipientEmail, tenant)
	data := emaildom.TeamInvitationData{
		Lang:          emaildom.Lang{Locale: loc},
		InviterName:   inviterName,
		TeamName:      teamName,
		InvitationURL: invitationURL,
		ExpiresIn:     emaildom.FormatDuration(loc, expiresIn),
		AppName:       s.appName,
		Branding:      s.branding,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateTeamInvitation, data); err != nil {
		s.logger.Error("failed to send team invitation email",
			"email", logSafe(recipientEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send team invitation email: %w", err)
	}

	s.logger.Info("team invitation email sent",
		"email", logSafe(recipientEmail),
		"team", teamName,
		"tenant_smtp", len(tenantID) > 0 && tenantID[0] != "",
	)
	return nil
}

// The methods below make EmailService an auth.SecurityNotifier. They send in
// the background (the change they report is already committed) and only log
// failures, so a slow or broken SMTP server never fails the user's request.

// NotifyMFADisabled tells the user 2FA was turned off on their account.
func (s *EmailService) NotifyMFADisabled(ctx context.Context, userEmail, userName, ipAddress string) {
	loc := s.localeForEmail(ctx, userEmail, "")
	s.sendSecurityNotice(ctx, loc, userEmail, userName, ipAddress,
		emaildom.Text(loc, "notice.mfaOff.subject"),
		emaildom.Text(loc, "notice.mfaOff.message"))
}

// NotifyRecoveryCodeUsed tells the user a recovery code was used to sign in.
func (s *EmailService) NotifyRecoveryCodeUsed(ctx context.Context, userEmail, userName, ipAddress string, remaining int) {
	loc := s.localeForEmail(ctx, userEmail, "")
	s.sendSecurityNotice(ctx, loc, userEmail, userName, ipAddress,
		emaildom.Text(loc, "notice.recovery.subject"),
		emaildom.Text(loc, "notice.recovery.message", remaining))
}

// NotifyIdentityLinked tells the user a social sign-in method was linked.
func (s *EmailService) NotifyIdentityLinked(ctx context.Context, userEmail, userName, ipAddress, provider string) {
	loc := s.localeForEmail(ctx, userEmail, "")
	s.sendSecurityNotice(ctx, loc, userEmail, userName, ipAddress,
		emaildom.Text(loc, "notice.idLinked.subject", provider),
		emaildom.Text(loc, "notice.idLinked.message", provider))
}

// NotifyIdentityUnlinked tells the user a social sign-in method was removed.
func (s *EmailService) NotifyIdentityUnlinked(ctx context.Context, userEmail, userName, ipAddress, provider string) {
	loc := s.localeForEmail(ctx, userEmail, "")
	s.sendSecurityNotice(ctx, loc, userEmail, userName, ipAddress,
		emaildom.Text(loc, "notice.idUnlinked.subject", provider),
		emaildom.Text(loc, "notice.idUnlinked.message", provider))
}

// NotifyPasswordChanged sends the existing password-changed email.
func (s *EmailService) NotifyPasswordChanged(ctx context.Context, userEmail, userName, ipAddress string) {
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	go func() {
		defer cancel()
		_ = s.SendPasswordChangedEmail(bg, userEmail, userName, ipAddress)
	}()
}

// NotifySSOChangePending tells an organization owner that a platform
// administrator proposed an SSO change that waits for their approval. summary
// never contains a secret.
func (s *EmailService) NotifySSOChangePending(ctx context.Context, ownerEmail, ownerName, orgName, summary string) {
	loc := s.localeForEmail(ctx, ownerEmail, "")
	s.sendSecurityNotice(ctx, loc, ownerEmail, ownerName, "",
		emaildom.Text(loc, "notice.ssoPending.subject", orgName),
		summary+" "+emaildom.Text(loc, "notice.ssoPending.suffix"))
}

// NotifySAMLCertificateExpiry tells an organization owner that the SAML
// identity provider's signing certificate expires soon or has expired.
func (s *EmailService) NotifySAMLCertificateExpiry(ctx context.Context, ownerEmail, ownerName, subject, message string) {
	s.sendSecurityNotice(ctx, s.localeForEmail(ctx, ownerEmail, ""), ownerEmail, ownerName, "", subject, message)
}

// NotifyEmailRelayStopped tells an organization owner that an e-mail channel
// was stopped because its mail server no longer meets the service rules. It
// goes through the platform relay, never the organization's.
func (s *EmailService) NotifyEmailRelayStopped(ctx context.Context, ownerEmail, ownerName, subject, message string) {
	s.sendSecurityNotice(ctx, s.localeForEmail(ctx, ownerEmail, ""), ownerEmail, ownerName, "", subject, message)
}

// NotifySupportAccess tells an organization owner about support access:
// a grant, a revocation, a support session opened or ended.
func (s *EmailService) NotifySupportAccess(ctx context.Context, email, name, subject, message string) {
	s.sendSecurityNotice(ctx, s.localeForEmail(ctx, email, ""), email, name, "", subject, message)
}

// NotifyOwnershipTransfer tells one of the two people in an ownership
// transfer what happened (requested, canceled, declined, accepted).
func (s *EmailService) NotifyOwnershipTransfer(ctx context.Context, email, name, subject, message string) {
	s.sendSecurityNotice(ctx, s.localeForEmail(ctx, email, ""), email, name, "", subject, message)
}

// SendOwnershipInvitation tells an existing account that a platform
// administrator created organizationName for it and invites it to be the
// owner. The message links to the page where the person accepts or declines
// after signing in; it carries no token (the invitation is bound to the
// account).
func (s *EmailService) SendOwnershipInvitation(ctx context.Context, email, name, organizationName string, expiresAt time.Time) {
	link := fmt.Sprintf("%s/ownership-invitations", strings.TrimSuffix(s.config.BaseURL, "/"))
	loc := s.localeForEmail(ctx, email, "")
	s.sendSecurityNotice(ctx, loc, email, name, "",
		emaildom.Text(loc, "notice.ownership.subject"),
		emaildom.Text(loc, "notice.ownership.message", organizationName, link, emaildom.FormatDate(loc, expiresAt.UTC())))
}

func (s *EmailService) sendSecurityNotice(ctx context.Context, loc, userEmail, userName, ipAddress, subject, message string) {
	if !s.IsConfigured() {
		return
	}
	data := emaildom.SecurityNoticeData{
		Lang:       emaildom.Lang{Locale: loc},
		UserName:   userName,
		Email:      userEmail,
		Subject:    subject,
		Message:    message,
		OccurredAt: emaildom.FormatTime(loc, time.Now().UTC()),
		IPAddress:  ipAddress,
		AppName:    s.appName,
		Branding:   s.branding,
	}
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	go func() {
		defer cancel()
		if err := s.sender.SendTemplate(bg, userEmail, emaildom.TemplateSecurityNotice, data); err != nil {
			s.logger.Error("failed to send security notice email", "error", err)
		}
	}()
}

// logSafe strips line breaks from a caller-supplied value before it is
// logged, so it cannot forge log entries (CWE-117). strings.ReplaceAll on
// \n and \r is the sanitizer CodeQL recognizes.
func logSafe(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "\n", ""), "\r", "")
}

// SendDomainManagedEmail tells an account that the organization which
// verified its email domain now manages accounts on it: the next sign-in may
// go through that organization's single sign-on, or new organizations may be
// blocked. Nothing is moved: the account's other organizations stay its own.
// The message names only the domain.
func (s *EmailService) SendDomainManagedEmail(ctx context.Context, userEmail, domain string) error {
	if !s.IsConfigured() {
		return fmt.Errorf("email: no SMTP sender configured")
	}
	loginURL := fmt.Sprintf("%s/login", strings.TrimSuffix(s.config.BaseURL, "/"))
	loc := s.localeForEmail(ctx, userEmail, "")
	body := "<p>" + string(emaildom.TextHTML(loc, "domainManaged.body1", domain, s.appName)) + "</p>\n" +
		"<p>" + emaildom.Text(loc, "domainManaged.body2") + "</p>\n" +
		"<p><a href=\"" + html.EscapeString(loginURL) + "\">" + emaildom.Text(loc, "domainManaged.signIn") + "</a></p>"
	return s.sender.Send(ctx, &emaildom.Message{
		To:      []string{userEmail},
		Subject: emaildom.Text(loc, "domainManaged.subject", s.appName, domain),
		Body:    body,
		IsHTML:  true,
	})
}

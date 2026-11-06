package main

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// adminAccountDirectory lets the admin console (RFC-022) check an account's
// password for its own sign-in and provision the users-table account a new
// platform administrator signs in with. The console owns the second factor
// and the admin_users link; everything about the account itself stays with
// AuthService.
type adminAccountDirectory struct {
	auth *authapp.AuthService
}

var _ adminconsole.AccountDirectory = adminAccountDirectory{}

func (d adminAccountDirectory) VerifyPassword(ctx context.Context, email, password string, client adminconsole.ClientInfo) (*adminconsole.SignedInUser, error) {
	u, err := d.auth.VerifyConsolePassword(ctx, email, password, client.IP, client.UserAgent)
	switch {
	case err == nil:
	case errors.Is(err, authapp.ErrAccountLocked):
		return nil, admin.ErrAccountLocked
	default:
		// Wrong password, unknown email, suspended or not a local account:
		// one answer.
		return nil, admin.ErrInvalidCredentials
	}
	return &adminconsole.SignedInUser{UserID: u.ID(), Email: u.Email(), Name: u.Name(), Active: u.CanLogin()}, nil
}

func (d adminAccountDirectory) RecordPasswordSuccess(ctx context.Context, userID shared.ID) {
	d.auth.RecordConsolePasswordSuccess(ctx, userID)
}

func (d adminAccountDirectory) RecordPasswordFailure(ctx context.Context, userID shared.ID) {
	d.auth.RecordConsolePasswordFailure(ctx, userID)
}

func (d adminAccountDirectory) CreateInvitedAccount(ctx context.Context, email, name string, ttl time.Duration) (shared.ID, adminconsole.Invitation, error) {
	acc, err := d.auth.CreateInvitedAccount(ctx, email, name, ttl)
	if err != nil {
		if errors.Is(err, authapp.ErrEmailAlreadyExists) {
			return shared.ID{}, adminconsole.Invitation{}, admin.ErrEmailHasAccount
		}
		return shared.ID{}, adminconsole.Invitation{}, err
	}
	return acc.User.ID(), adminconsole.Invitation{Token: acc.SetupToken, ExpiresAt: acc.ExpiresAt}, nil
}

// adminInvitationMailer delivers a new administrator's set-password link
// through the platform's system SMTP.
type adminInvitationMailer struct {
	email *authapp.EmailService
}

var _ adminconsole.InvitationMailer = adminInvitationMailer{}

func (m adminInvitationMailer) CanDeliver(context.Context) bool {
	return m.email != nil && m.email.CanDeliverSystem()
}

func (m adminInvitationMailer) SetupURL(token string) string {
	if m.email == nil {
		return ""
	}
	return m.email.AccountSetupURL(token)
}

func (m adminInvitationMailer) SendAdminInvitation(ctx context.Context, email, name, token string, expiresIn time.Duration) error {
	if m.email == nil {
		return errors.New("platform e-mail is not available")
	}
	return m.email.SendAdminInvitationEmail(ctx, email, name, token, expiresIn)
}

func (d adminAccountDirectory) AccountActive(ctx context.Context, userID shared.ID) (bool, error) {
	return d.auth.AccountActive(ctx, userID)
}

func (d adminAccountDirectory) ChangePassword(ctx context.Context, userID shared.ID, current, next string) error {
	return d.auth.ChangePassword(ctx, userID.String(), authapp.ChangePasswordInput{CurrentPassword: current, NewPassword: next})
}

// breakGlassChecker tells the main-site sign-in paths whether an account is
// linked to a break-glass administrator (console only). A lookup failure other
// than "no administrator" refuses: the gate fails closed.
type breakGlassChecker struct {
	admins admin.Repository
}

func (c breakGlassChecker) IsBreakGlass(ctx context.Context, userID shared.ID) bool {
	a, err := c.admins.GetByUserID(ctx, userID)
	if err != nil {
		return !errors.Is(err, admin.ErrAdminNotFound)
	}
	return a.IsBreakGlass()
}

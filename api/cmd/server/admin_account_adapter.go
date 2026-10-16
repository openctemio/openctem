package main

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
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

func (d adminAccountDirectory) CreateAccount(ctx context.Context, email, name string) (shared.ID, string, error) {
	acc, err := d.auth.CreateLocalAccount(ctx, email, name)
	if err != nil {
		if errors.Is(err, authapp.ErrEmailAlreadyExists) {
			return shared.ID{}, "", admin.ErrEmailHasAccount
		}
		return shared.ID{}, "", err
	}
	return acc.User.ID(), acc.TemporaryPassword, nil
}

func (d adminAccountDirectory) AccountActive(ctx context.Context, userID shared.ID) (bool, error) {
	return d.auth.AccountActive(ctx, userID)
}

func (d adminAccountDirectory) ChangePassword(ctx context.Context, userID shared.ID, current, next string) error {
	return d.auth.ChangePassword(ctx, userID.String(), authapp.ChangePasswordInput{CurrentPassword: current, NewPassword: next})
}

// platformAdminChecker tells login and /users/me whether an account is linked
// to an active platform administrator, so the UI can route it to the console.
type platformAdminChecker struct {
	admins admin.Repository
}

var _ handler.PlatformAdminChecker = platformAdminChecker{}

func (c platformAdminChecker) IsPlatformAdmin(ctx context.Context, userID shared.ID) bool {
	a, err := c.admins.GetByUserID(ctx, userID)
	return err == nil && a.IsActive()
}

package main

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// adminAccountDirectory lets the admin console (RFC-022) resolve the user
// signed in on the normal /login page and provision the users-table account a
// new platform administrator signs in with. The console owns the second factor
// and the admin_users link; everything about the account itself stays with
// AuthService.
type adminAccountDirectory struct {
	auth *authapp.AuthService
}

var _ adminconsole.AccountDirectory = adminAccountDirectory{}

func (d adminAccountDirectory) SignedInUser(ctx context.Context, refreshToken string) (*adminconsole.SignedInUser, error) {
	id, err := d.auth.IdentifyRefreshSession(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	u := id.User
	return &adminconsole.SignedInUser{
		UserID:         u.ID(),
		Email:          u.Email(),
		Name:           u.Name(),
		Active:         u.CanLogin(),
		PasswordSignIn: id.AuthMethod == sessiondom.AuthMethodPassword,
	}, nil
}

func (d adminAccountDirectory) EndSignIn(ctx context.Context, refreshToken string) error {
	id, err := d.auth.IdentifyRefreshSession(ctx, refreshToken)
	if err != nil {
		return err
	}
	return d.auth.Logout(ctx, id.SessionID.String())
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

package main

import (
	"context"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/adminconsole"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/pkg/domain/admin"
	sessiondom "github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
)

// adminAccountDirectory lets the admin console (RFC-022) resolve the user
// signed in on the normal /login page and provision the users-table account a
// new platform administrator signs in with. The console owns the second factor
// and the admin_users link; everything about the account itself stays with
// AuthService.
type adminAccountDirectory struct {
	auth *app.AuthService
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

func (d adminAccountDirectory) ProvisionAccount(ctx context.Context, email, name string) (shared.ID, string, error) {
	acc, err := d.auth.ProvisionLocalAccount(ctx, email, name)
	if err != nil {
		return shared.ID{}, "", err
	}
	return acc.User.ID(), acc.TemporaryPassword, nil
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

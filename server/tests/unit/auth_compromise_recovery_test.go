package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// recordingKeys is an APIKeyRevoker that records which users' keys it
// revoked.
type recordingKeys struct{ revoked []string }

func (r *recordingKeys) RevokeAllForUser(_ context.Context, id shared.ID) (int, error) {
	r.revoked = append(r.revoked, id.String())
	return 2, nil
}
func (r *recordingKeys) CountActiveForUser(context.Context, shared.ID) (int, error) { return 2, nil }

// hookLog records the order and the user of every sessions-revoked hook.
func hookLog(svc *auth.AuthService) *[]string {
	var got []string
	svc.AddSessionsRevokedHook(func(_ context.Context, id shared.ID) { got = append(got, "console:"+id.String()) })
	svc.AddSessionsRevokedHook(func(_ context.Context, id shared.ID) { got = append(got, "mcp:"+id.String()) })
	return &got
}

// A password reset runs every hook (console sessions AND connected
// applications) for exactly the account being reset, and revokes API keys
// only when the request asks for it.
func TestResetPassword_RunsAllHooksAndKeysOnlyWhenAsked(t *testing.T) {
	for _, asked := range []bool{false, true} {
		svc, deps, _, _ := newResetAuditHarness()
		u := seedAuthUserWithResetToken(deps.userRepo, "victim@example.com", "$2a$04$dummy", "tok-r")
		other := seedAuthUserWithResetToken(deps.userRepo, "bystander@example.com", "$2a$04$dummy", "tok-o")
		keys := &recordingKeys{}
		svc.SetAPIKeyRevoker(keys)
		got := hookLog(svc)

		if err := svc.ResetPassword(context.Background(), auth.ResetPasswordInput{Token: "tok-r", NewPassword: "NewStrongPassword123!", RevokeAPIKeys: asked}); err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}
		want := []string{"console:" + u.ID().String(), "mcp:" + u.ID().String()}
		if len(*got) != 2 || (*got)[0] != want[0] || (*got)[1] != want[1] {
			t.Fatalf("hooks must run in order for the one account, got %v want %v", *got, want)
		}
		for _, h := range *got {
			if h == "console:"+other.ID().String() || h == "mcp:"+other.ID().String() {
				t.Fatalf("another user's grants were touched: %v", *got)
			}
		}
		if asked != (len(keys.revoked) == 1 && keys.revoked[0] == u.ID().String()) || (!asked && len(keys.revoked) != 0) {
			t.Fatalf("API keys revoked=%v with revoke_api_keys=%v", keys.revoked, asked)
		}
	}
}

// Changing the password does the same, and keeps the current session.
func TestChangePassword_RunsAllHooksAndKeysOnlyWhenAsked(t *testing.T) {
	for _, asked := range []bool{false, true} {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "chg@example.com")
		cur := h.login(t, "chg@example.com")
		keys := &recordingKeys{}
		h.svc.SetAPIKeyRevoker(keys)
		got := hookLog(h.svc)

		if err := h.svc.ChangePassword(context.Background(), uid.String(), auth.ChangePasswordInput{
			CurrentPassword: mfaTestPassword, NewPassword: "AnotherPassword456", CurrentSessionID: cur.SessionID, RevokeAPIKeys: asked,
		}); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}
		if len(*got) != 2 || (*got)[1] != "mcp:"+uid.String() {
			t.Fatalf("connected applications must be revoked on a password change, got %v", *got)
		}
		if asked && len(keys.revoked) != 1 || !asked && len(keys.revoked) != 0 {
			t.Fatalf("API keys revoked=%v with revoke_api_keys=%v", keys.revoked, asked)
		}
	}
}

// Sign out everywhere runs the same hooks for the caller only.
func TestSignOutEverywhere_RunsHooksAndKeysOnlyWhenAsked(t *testing.T) {
	for _, asked := range []bool{false, true} {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "out@example.com")
		cur := h.login(t, "out@example.com")
		h.login(t, "out@example.com")
		keys := &recordingKeys{}
		h.svc.SetAPIKeyRevoker(keys)
		got := hookLog(h.svc)
		sess := auth.NewSessionService(h.sessions, newMockAuthRefreshTokenRepo(), logger.NewNop())
		sess.SetSessionsRevokedHooks(h.svc.SessionsRevoked())

		res, err := sess.SignOutEverywhere(context.Background(), uid.String(), cur.SessionID, asked)
		if err != nil {
			t.Fatalf("SignOutEverywhere: %v", err)
		}
		if len(*got) != 2 || (*got)[1] != "mcp:"+uid.String() {
			t.Fatalf("hooks: %v", *got)
		}
		if asked && (res.APIKeysRevoked != 2 || len(keys.revoked) != 1) || !asked && (res.APIKeysRevoked != 0 || len(keys.revoked) != 0) {
			t.Fatalf("keys: result=%d revoked=%v asked=%v", res.APIKeysRevoked, keys.revoked, asked)
		}
	}
}

// suspend replaces the stored account with a copy whose status is suspended
// (a platform block), keeping its id and password.
func suspend(t *testing.T, users *mockAuthUserRepo, id shared.ID) {
	t.Helper()
	u := users.users[id.String()]
	now := time.Now().UTC()
	users.users[id.String()] = user.Reconstitute(id, nil, u.Email(), u.Name(), "", "", user.StatusSuspended,
		user.Preferences{}, nil, now, now, user.AuthProviderLocal, u.PasswordHash(), true, nil, nil, nil, nil, 0, nil)
}

// A blocked account's refresh token exchanges nothing and refreshes nothing,
// even when the session was opened before the block.
func TestExchangeAndRefresh_BlockedUserRefused(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "blocked@example.com")
	res := h.login(t, "blocked@example.com")
	suspend(t, h.users, uid)

	tenant := shared.NewID().String()
	if _, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: tenant}); !errors.Is(err, auth.ErrAccountSuspended) {
		t.Fatalf("exchange for a blocked user: want ErrAccountSuspended, got %v", err)
	}
	if _, err := h.svc.RefreshToken(context.Background(), auth.RefreshTokenInput{RefreshToken: res.RefreshToken, TenantID: tenant}); !errors.Is(err, auth.ErrAccountSuspended) {
		t.Fatalf("refresh for a blocked user: want ErrAccountSuspended, got %v", err)
	}
}

// Approving a connector consent mints a 90-day grant with the caller's
// permissions, so it needs a recent sign-in like the other persistent
// credentials. The method name (Approve) is shared by unrelated services, so
// the service-action inventory cannot carry it; this pins the route.
func TestMCPConsentApproveRequiresStepUp(t *testing.T) {
	found := false
	for _, r := range parseRoutes(t) {
		if r.method == "POST" && r.path == "/api/v1/oauth/requests/{id}/approve" {
			found = true
			if !r.stepUp {
				t.Errorf("%s %s (%s) must require requireStepUp()", r.method, r.path, r.pos)
			}
		}
	}
	if !found {
		t.Fatal("consent approve route not found: update this test if it moved")
	}
}

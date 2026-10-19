package unit

import (
	"context"
	"errors"
	"testing"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type reuseAuditRepo struct {
	mockAuthAuditRepo
	logs []*audit.AuditLog
}

func (r *reuseAuditRepo) Create(_ context.Context, l *audit.AuditLog) error {
	r.logs = append(r.logs, l)
	return nil
}

// spendStoredToken marks the stored row of a raw refresh token as already
// rotated, the state a stolen copy is in once the real client refreshed.
func spendStoredToken(t *testing.T, deps *authTestDeps, raw string) {
	t.Helper()
	tok, err := deps.rtRepo.GetByTokenHash(context.Background(), session.HashToken(raw))
	if err != nil {
		t.Fatalf("stored token: %v", err)
	}
	if err := tok.MarkUsed(); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
}

// A refresh token presented after rotation ends the whole session, on every
// path that accepts one, and is audited. Before, only the token family was
// revoked: the session stayed active and its access tokens kept working
// until they expired; the first-team and invitation paths did not even
// revoke the family.
func TestAuthService_RefreshTokenReuseEndsSession(t *testing.T) {
	type call func(svc *auth.AuthService, rt string) error
	tenantID := shared.NewID().String()
	paths := map[string]call{
		"refresh": func(svc *auth.AuthService, rt string) error {
			_, err := svc.RefreshToken(context.Background(), auth.RefreshTokenInput{RefreshToken: rt, TenantID: tenantID})
			return err
		},
		"exchange": func(svc *auth.AuthService, rt string) error {
			_, err := svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: rt, TenantID: tenantID})
			return err
		},
		"identify": func(svc *auth.AuthService, rt string) error {
			_, err := svc.IdentifyRefreshSession(context.Background(), rt)
			return err
		},
		"first-team": func(svc *auth.AuthService, rt string) error {
			_, err := svc.CreateFirstTeam(context.Background(), auth.CreateFirstTeamInput{RefreshToken: rt, TeamName: "Team", TeamSlug: "team-x"})
			return err
		},
	}
	for name, run := range paths {
		t.Run(name, func(t *testing.T) {
			cfg := defaultAuthTestConfig()
			deps := &authTestDeps{
				userRepo: newMockAuthUserRepo(), sessionRepo: newMockAuthSessionRepo(),
				rtRepo: newMockAuthRefreshTokenRepo(), tenantRepo: newMockAuthTenantRepo(), cfg: cfg,
			}
			rec := &reuseAuditRepo{}
			log := logger.NewNop()
			svc := auth.NewAuthService(deps.userRepo, deps.sessionRepo, deps.rtRepo, deps.tenantRepo,
				auditsvc.NewAuditService(rec, log), cfg, log)

			rt, sid := loginPassword(t, svc, deps, name+"@example.com")
			spendStoredToken(t, deps, rt)

			err := run(svc, rt)
			if !errors.Is(err, session.ErrRefreshTokenUsed) && !errors.Is(err, session.ErrRefreshTokenRevoked) {
				t.Fatalf("expected a used/revoked refusal, got %v", err)
			}
			if deps.sessionRepo.sessions[sid].IsActive() {
				t.Fatal("the session must be revoked")
			}
			if deps.rtRepo.revokeByFamilyCalls != 1 || deps.rtRepo.revokeBySessionCalls != 1 {
				t.Fatalf("family and session tokens must be revoked, got family=%d session=%d",
					deps.rtRepo.revokeByFamilyCalls, deps.rtRepo.revokeBySessionCalls)
			}
			found := false
			for _, l := range rec.logs {
				if l.Action() == audit.ActionAuthSessionRevoked && l.Metadata()["reason"] == "refresh_token_reuse" {
					found = true
				}
			}
			if !found {
				t.Fatal("the reuse must be audited")
			}
		})
	}
}

// The exchange spends the presented token before it mints: a failure to
// record that refuses the exchange instead of leaving the old token usable.
func TestAuthService_ExchangeToken_RotationFailureRefuses(t *testing.T) {
	svc, deps := newTestAuthService()
	rt, _ := loginPassword(t, svc, deps, "rotate@example.com")
	tn := mustNewEnforcedTenant(t, deps.tenantRepo, "rotate-org", false)
	deps.tenantRepo.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), Role: "member"}}
	deps.rtRepo.updateErr = errors.New("db down")

	if _, err := svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: rt, TenantID: tn.ID().String()}); err == nil {
		t.Fatal("the exchange must fail when the old token cannot be marked used")
	}
}

// Two concurrent refreshes of one token both pass the read-time checks; the
// loser of the conditional spend is a reuse and ends the session, so the
// family never forks.
func TestAuthService_RefreshToken_LostSpendRaceIsReuse(t *testing.T) {
	svc, deps := newTestAuthService()
	rt, sid := loginPassword(t, svc, deps, "race@example.com")
	deps.rtRepo.lostSpendRace = true

	_, err := svc.RefreshToken(context.Background(), auth.RefreshTokenInput{RefreshToken: rt, TenantID: shared.NewID().String()})
	if !errors.Is(err, session.ErrRefreshTokenRevoked) {
		t.Fatalf("lost spend race: want ErrRefreshTokenRevoked, got %v", err)
	}
	if deps.sessionRepo.sessions[sid].IsActive() {
		t.Fatal("the session must be revoked")
	}
	if deps.rtRepo.revokeByFamilyCalls != 1 {
		t.Fatalf("family must be revoked once, got %d", deps.rtRepo.revokeByFamilyCalls)
	}
}

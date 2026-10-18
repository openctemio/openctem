package main

import (
	"github.com/openctemio/openctem/api/internal/app/platformuser"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// newPlatformUserService wires Console > Users support actions. A missing
// session, auth or email service leaves the matching action unavailable
// (refused), never unchecked. The nil checks keep typed-nil pointers out of
// the interfaces.
func newPlatformUserService(repos *Repositories, svc *Services, cfg *config.Config, db *postgres.DB, log *logger.Logger) *platformuser.Service {
	var (
		sessions platformuser.SessionRevoker
		resets   platformuser.ResetIssuer
		mailer   platformuser.Mailer
	)
	if svc.Session != nil {
		sessions = svc.Session
	}
	if svc.Auth != nil {
		resets = svc.Auth
	}
	if svc.Email != nil {
		mailer = svc.Email
	}
	dir := postgres.NewPlatformUserDirectory(db)
	s := platformuser.NewService(repos.User, sessions, resets, mailer, dir,
		platformuser.Durations{
			PasswordReset:     cfg.Auth.PasswordResetDuration,
			EmailVerification: cfg.Auth.EmailVerificationDuration,
		})
	// Block / unblock an account platform-wide (critical admin audit).
	s.SetBlocking(dir, repos.AdminAuditLog, log)
	return s
}

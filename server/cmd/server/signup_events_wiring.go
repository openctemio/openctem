package main

import (
	signupeventapp "github.com/openctemio/openctem/api/internal/app/signupevent"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/internal/infra/telemetry"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// wireSignupEvents builds the console's sign-up feed and burst alerts
// (docs/architecture/signup-activity.md) and hands the recorder to every
// path that creates an account, an organization or an access request. The
// window counters live in Redis (shared by every replica); without Redis the
// events are still recorded and the burst alerts are off.
func wireSignupEvents(svc *Services, repos *Repositories, redisClient *redis.Client, cfg *config.Config, log *logger.Logger) {
	if repos.SignupEvent == nil {
		return
	}
	svc.SignupEvents = signupeventapp.NewService(repos.SignupEvent, repos.SignupEvent, repos.AdminAuditLog, log)
	s := svc.SignupEvents
	if redisClient != nil {
		svc.SignupEvents.SetBurstCounter(redis.NewSharedAnomalyCounter(redisClient), telemetry.SignupMetrics{})
	} else {
		log.Warn("Redis not configured: sign-up burst alerts are off")
	}
	if repos.Admin != nil && svc.Email != nil {
		svc.SignupEvents.SetNotifier(systemMailer{admins: repos.Admin, email: svc.Email, appName: cfg.Brand.DisplayName(), log: log})
	}

	if svc.Auth != nil {
		svc.Auth.SetSignupRecorder(s)
	}
	if svc.OAuth != nil {
		svc.OAuth.SetSignupRecorder(s)
	}
	if svc.SSO != nil {
		svc.SSO.SetSignupRecorder(s)
	}
	if svc.Tenant != nil {
		svc.Tenant.SetSignupRecorder(s)
	}
	if svc.AccessRequest != nil {
		svc.AccessRequest.SetSignupRecorder(s)
	}
}

package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/internal/app/deploymentregion"
	"github.com/openctemio/openctem/api/internal/app/platformai"
	"github.com/openctemio/openctem/api/internal/app/platformalert"
	"github.com/openctemio/openctem/api/internal/app/platformcaptcha"
	"github.com/openctemio/openctem/api/internal/app/systemstatus"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// initConsoleSettings builds the settings that moved from the environment
// into the console (RFC-079). The environment values stay as the lock
// (CAPTCHA keys, region, AI keys) or the default (storage quota).
func (s *Services) initConsoleSettings(cfg *config.Config, repos *Repositories, log *logger.Logger) {
	s.SettingRecorder = consolesetting.NewRecorder(repos.AdminAuditLog, nil, cfg.Brand.DisplayName(), log)
	if repos.PlatformSetting == nil {
		return
	}
	s.PlatformCaptcha = platformcaptcha.NewService(repos.PlatformSetting, s.Encryptor, s.SettingRecorder,
		cfg.Auth.CaptchaTurnstileSiteKey, cfg.Auth.CaptchaTurnstileSecret, log)
	s.DeploymentRegion = deploymentregion.NewService(repos.PlatformSetting, repos.Tenant, s.SettingRecorder, cfg.App.Region, log)
	s.PlatformAlert = platformalert.NewService(repos.PlatformSetting, s.Encryptor, s.SettingRecorder, log)
	s.PlatformAI = platformai.NewService(repos.PlatformSetting, s.Encryptor, s.SettingRecorder,
		cfg.AITriage.IsConfigured(), cfg.AITriage.PlatformProvider, cfg.AITriage.PlatformModel, log)
	// New organizations get the deployment's region, fixed for their life.
	region := s.DeploymentRegion
	repos.Tenant.SetRegionSource(region.Region)
}

// platformAITester is the console's key test: one minimal completion.
func platformAITester(f *llm.Factory) platformai.Tester {
	return func(ctx context.Context, p platformai.Platform) error {
		prov, err := f.BuildPlatformProvider(p.Provider, p.Model, p.APIKey)
		if err != nil {
			return err
		}
		_, err = prov.Complete(ctx, llm.CompletionRequest{UserPrompt: "Reply with OK.", MaxTokens: 1})
		return err
	}
}

// adminNotifier tells every administrator: e-mail, and the alert webhook
// when one is on. Nil parts are skipped.
type adminNotifier []systemstatus.Notifier

func (n adminNotifier) NotifyAdmins(ctx context.Context, subject, body string) error {
	var first error
	for _, x := range n {
		if x == nil {
			continue
		}
		if err := x.NotifyAdmins(ctx, subject, body); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// newAdminNotifier builds the notifier of the system watch and of console
// setting changes.
func newAdminNotifier(cfg *config.Config, repos *Repositories, svc *Services, log *logger.Logger) systemstatus.Notifier {
	var out adminNotifier
	if repos.Admin != nil && svc.Email != nil {
		out = append(out, systemMailer{admins: repos.Admin, email: svc.Email, appName: cfg.Brand.DisplayName(), log: log})
	}
	if svc.PlatformAlert != nil {
		out = append(out, svc.PlatformAlert)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// newAdminPlatformSettingsHandler serves the moved settings; nil when the
// console settings store is not configured.
func newAdminPlatformSettingsHandler(repos *Repositories, svc *Services, log *logger.Logger) *handler.AdminPlatformSettingsHandler {
	if repos.PlatformSetting == nil || repos.Admin == nil {
		return nil
	}
	h := handler.NewAdminPlatformSettingsHandler(repos.Admin, log)
	h.Captcha, h.Region, h.StorageQuota, h.Alerts, h.AI =
		svc.PlatformCaptcha, svc.DeploymentRegion, svc.StorageQuota, svc.PlatformAlert, svc.PlatformAI
	return h
}

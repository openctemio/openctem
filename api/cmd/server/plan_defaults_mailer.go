package main

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// planDefaultsMailer emails the other administrators when the plan defaults
// change (system SMTP; the WARN line alert=plan_defaults_changed is written
// either way).
type planDefaultsMailer struct {
	email   *auth.EmailService
	appName string
	log     *logger.Logger
}

var _ entitlement.ChangeNotifier = planDefaultsMailer{}

func (m planDefaultsMailer) NotifyPlanDefaultsChanged(_ context.Context, adminEmail string, recipients []string) error {
	if m.email == nil || !m.email.IsConfigured() {
		return nil
	}
	name := m.appName
	if name == "" {
		name = "OpenCTEM"
	}
	who := strings.NewReplacer("\r", "", "\n", "").Replace(adminEmail)
	subject := fmt.Sprintf("[%s] Plan limits changed by %s", name, who)
	body := fmt.Sprintf(`<p><strong>%s</strong> changed the plan limits on %s (Console &gt; System &gt; Plans).</p>
<p>Lower limits never remove members, assets or keys; they only block new additions over the limit. Review the change in the admin audit log.</p>`,
		html.EscapeString(who), html.EscapeString(name))
	to := append([]string(nil), recipients...)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", to, subject, body); err != nil {
			m.log.Warn("plan defaults change email failed", "error", err)
		}
	}()
	return nil
}

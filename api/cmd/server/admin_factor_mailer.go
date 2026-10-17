package main

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// adminFactorMailer emails an administrator when a security key is added to,
// or the recovery codes of, their own console account change. The system SMTP
// sender is used (there is no platform-level notification integration); the
// audit row is written either way.
type adminFactorMailer struct {
	email   *auth.EmailService
	appName string
	log     *logger.Logger
}

var _ adminconsole.FactorChangeNotifier = adminFactorMailer{}

func (m adminFactorMailer) NotifyFactorChange(_ context.Context, n adminconsole.FactorNotice) error {
	if m.email == nil || !m.email.IsConfigured() || n.AdminEmail == "" {
		m.log.Warn("console factor change: system SMTP is not configured, the administrator was not emailed", "kind", n.Kind)
		return nil
	}
	name := m.appName
	if name == "" {
		name = brand.DefaultName
	}
	oneLine := strings.NewReplacer("\r", "", "\n", "")
	var subject, what string
	switch n.Kind {
	case adminconsole.FactorKeyAdded:
		subject = fmt.Sprintf("[%s] A security key was added to your admin console account", name)
		what = fmt.Sprintf("A security key named <strong>%s</strong> was added to your %s admin console account.", html.EscapeString(oneLine.Replace(n.Detail)), html.EscapeString(name))
	case adminconsole.FactorRecoveryCodesRegenerated:
		subject = fmt.Sprintf("[%s] Your admin console recovery codes were regenerated", name)
		what = fmt.Sprintf("The recovery codes of your %s admin console account were regenerated; the previous codes no longer work.", html.EscapeString(name))
	default:
		return nil
	}
	body := fmt.Sprintf(`<p>%s</p><ul><li>Time: %s</li><li>IP address: %s</li></ul>
<p>If this was not you, treat it as an account takeover: ask another super admin to reset your console credentials and change your password.</p>`,
		what, html.EscapeString(n.At.UTC().Format(time.RFC1123)), html.EscapeString(oneLine.Replace(n.IP)))

	to := []string{n.AdminEmail}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", to, subject, body); err != nil {
			m.log.Warn("console factor change email failed", "kind", n.Kind, "error", err)
		}
	}()
	return nil
}

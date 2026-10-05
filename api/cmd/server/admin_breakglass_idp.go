package main

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// newPlatformIdPClient builds the OIDC client for the administrators' identity
// provider. The issuer is configured at runtime, so every URL is checked by
// httpsec.ValidateURL before it is dialed and the transport refuses blocked
// addresses after DNS resolution (httpsec.SafeHTTPClient).
func newPlatformIdPClient() *oidc.Client {
	return oidc.NewClient(httpsec.SafeHTTPClient(15*time.Second), func(raw string) error {
		_, err := httpsec.ValidateURL(raw)
		return err
	})
}

// breakGlassMailer emails the other administrators when a break-glass
// administrator signs in. There is no platform-level notification integration
// (integrations are per organization), so it uses the system SMTP sender. The
// console service always writes the WARN line with alert=break_glass_sign_in,
// so alerting works from logs when SMTP is not configured.
type breakGlassMailer struct {
	email   *auth.EmailService
	appName string
	log     *logger.Logger
}

var _ adminconsole.BreakGlassNotifier = breakGlassMailer{}

func (m breakGlassMailer) NotifyBreakGlassSignIn(_ context.Context, a adminconsole.BreakGlassAlert) error {
	if m.email == nil || !m.email.IsConfigured() {
		m.log.Warn("break-glass sign-in: system SMTP is not configured, administrators were not emailed",
			"alert", adminconsole.AlertBreakGlassSignIn)
		return nil
	}
	name := m.appName
	if name == "" {
		name = "OpenCTEM"
	}
	who := strings.NewReplacer("\r", "", "\n", "").Replace(a.AdminEmail)
	subject := fmt.Sprintf("[%s] Break-glass administrator sign-in: %s", name, who)
	body := fmt.Sprintf(`<p>The break-glass (emergency access) administrator <strong>%s</strong> signed in to the %s admin console.</p>
<ul><li>Time: %s</li><li>IP address: %s</li></ul>
<p>Break-glass accounts are for emergencies and periodic tests only. If this sign-in was not expected, treat it as an incident: deactivate the account in the console and rotate its password.</p>
<p>If it was a planned test, another super admin can record it on the Administrators page.</p>`,
		html.EscapeString(who), html.EscapeString(name),
		html.EscapeString(a.At.UTC().Format(time.RFC1123)), html.EscapeString(a.IP))

	// Never hold up the sign-in on SMTP.
	recipients := append([]string(nil), a.Recipients...)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", recipients, subject, body); err != nil {
			m.log.Warn("break-glass sign-in email failed", "alert", adminconsole.AlertBreakGlassSignIn, "error", err)
			return
		}
		m.log.Info("break-glass sign-in email sent", "alert", adminconsole.AlertBreakGlassSignIn, "recipients", len(recipients))
	}()
	return nil
}

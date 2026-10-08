package main

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/signup"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// signupPolicyMailer emails the other administrators when the sign-up policy
// changes. Like the break-glass alert it uses the system SMTP sender; the
// service always writes the WARN line with alert=signup_policy_changed, so
// alerting works from logs when SMTP is not configured.
type signupPolicyMailer struct {
	email   *auth.EmailService
	appName string
	log     *logger.Logger
}

var _ signup.ChangeNotifier = signupPolicyMailer{}

func describeSignupPolicy(p signupdom.Policy) string {
	mode := "Only platform administrators create organizations"
	if p.AllowsSelfService() {
		mode = "Anyone may sign up and create an organization"
	}
	if p.RequestAccess {
		return mode + "; people may request access"
	}
	return mode
}

func (m signupPolicyMailer) NotifySignupPolicyChanged(_ context.Context, a signup.ChangeAlert) error {
	if m.email == nil || !m.email.IsConfigured() {
		m.log.Warn("sign-up policy change: system SMTP is not configured, administrators were not emailed",
			"alert", signup.AlertPolicyChanged)
		return nil
	}
	name := m.appName
	if name == "" {
		name = defaultAppName
	}
	who := strings.NewReplacer("\r", "", "\n", "").Replace(a.AdminEmail)
	subject := fmt.Sprintf("[%s] Sign-up policy changed by %s", name, who)
	body := fmt.Sprintf(`<p><strong>%s</strong> changed who may create an organization on %s.</p>
<ul><li>Before: %s</li><li>Now: %s</li><li>Time: %s</li><li>IP address: %s</li></ul>
<p>Existing organizations, users and sessions are not affected. If this change was not expected, review it in the admin console (System &gt; Sign-up) and the admin audit log.</p>`,
		html.EscapeString(who), html.EscapeString(name),
		html.EscapeString(describeSignupPolicy(a.Previous)), html.EscapeString(describeSignupPolicy(a.Current)),
		html.EscapeString(a.At.UTC().Format(time.RFC1123)), html.EscapeString(a.IP))

	recipients := append([]string(nil), a.Recipients...)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", recipients, subject, body); err != nil {
			m.log.Warn("sign-up policy change email failed", "alert", signup.AlertPolicyChanged, "error", err)
		}
	}()
	return nil
}

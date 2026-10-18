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

// rosterChangeMailer emails the other administrators when one of them changes
// who may administer the platform or how administrators sign in. Like the
// break-glass notice it uses the platform e-mail; the console service always
// writes the WARN line with alert=admin_roster_change, so alerting works
// from logs when e-mail is not configured.
type rosterChangeMailer struct {
	email   *auth.EmailService
	appName string
	log     *logger.Logger
}

var _ adminconsole.RosterChangeNotifier = rosterChangeMailer{}

func (m rosterChangeMailer) NotifyRosterChange(_ context.Context, c adminconsole.RosterChange) error {
	if m.email == nil || !m.email.IsConfigured() {
		m.log.Warn("administrator roster change: platform e-mail is not configured, administrators were not emailed",
			"alert", adminconsole.AlertRosterChange)
		return nil
	}
	name := m.appName
	if name == "" {
		name = brand.DefaultName
	}
	oneLine := strings.NewReplacer("\r", "", "\n", "")
	who := oneLine.Replace(c.ActorEmail)
	subject := fmt.Sprintf("[%s] Administrator change by %s", name, who)
	body := fmt.Sprintf(`<p><strong>%s</strong> %s in the %s admin console.</p>
<ul><li>Time: %s</li><li>IP address: %s</li></ul>
<p>Every change to the administrators, their sign-in or the console sign-in policy is sent to all administrators. If you did not expect this one, treat it as an incident: review the admin activity log and end the administrator's sessions.</p>`,
		html.EscapeString(who), html.EscapeString(oneLine.Replace(c.Summary)), html.EscapeString(name),
		html.EscapeString(c.At.UTC().Format(time.RFC1123)), html.EscapeString(c.IP))

	// Never hold up the change on SMTP.
	recipients := append([]string(nil), c.Recipients...)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", recipients, subject, body); err != nil {
			m.log.Warn("administrator roster change email failed", "alert", adminconsole.AlertRosterChange, "error", err)
			return
		}
		m.log.Info("administrator roster change email sent", "alert", adminconsole.AlertRosterChange, "recipients", len(recipients))
	}()
	return nil
}

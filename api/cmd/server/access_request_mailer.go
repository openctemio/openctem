package main

import (
	"context"
	"fmt"
	"html"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accessrequest"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// accessRequestMailer sends the requester's emails through the system SMTP
// sender. Sending is asynchronous: the public answer must not wait on, or
// reveal anything through, SMTP.
type accessRequestMailer struct {
	email   *auth.EmailService
	appName string
	log     *logger.Logger
}

var _ accessrequest.Mailer = accessRequestMailer{}

func (m accessRequestMailer) Configured() bool { return m.email != nil && m.email.IsConfigured() }

func (m accessRequestMailer) name() string {
	if m.appName == "" {
		return defaultAppName
	}
	return m.appName
}

func (m accessRequestMailer) send(to, subject, body string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", []string{to}, subject, body); err != nil {
			m.log.Warn("access request email failed", "error", logger.SanitizeError(err))
		}
	}()
}

func (m accessRequestMailer) SendConfirmation(_ context.Context, to, company, confirmURL string) error {
	if !m.Configured() {
		return nil
	}
	subject := fmt.Sprintf("[%s] Confirm your access request", m.name())
	body := fmt.Sprintf(`<p>Someone asked for an organization on %s for <strong>%s</strong> with this email address.</p>
<p>If it was you, confirm the request: <a href="%s">%s</a></p>
<p>The link expires in 24 hours. If it was not you, ignore this email; the request is deleted.</p>`,
		html.EscapeString(m.name()), html.EscapeString(company), html.EscapeString(confirmURL), html.EscapeString(confirmURL))
	m.send(to, subject, body)
	return nil
}

func (m accessRequestMailer) SendDecision(_ context.Context, to string, approved bool) error {
	if !m.Configured() || approved {
		// An approval sends the owner's set-up link (OrganizationCreator).
		return nil
	}
	subject := fmt.Sprintf("[%s] Your access request", m.name())
	body := fmt.Sprintf(`<p>Thank you for your interest in %s. Your request for an organization was not approved.</p>
<p>If you think this is a mistake, contact your administrator.</p>`, html.EscapeString(m.name()))
	m.send(to, subject, body)
	return nil
}

// defaultAppName names the product in emails when APP_NAME is unset.
const defaultAppName = "OpenCTEM"

package main

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/lifecycle"
	lifecycledom "github.com/openctemio/openctem/api/pkg/domain/lifecycle"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// idleWorkspaceMailer emails the idle-workspace notices (system SMTP): the
// owners and admins for the reminder, read-only and final warning, the
// platform administrators for deletion_due.
type idleWorkspaceMailer struct {
	email   *auth.EmailService
	appName string
	baseURL string
	log     *logger.Logger
}

var _ lifecycle.Notifier = idleWorkspaceMailer{}

func (m idleWorkspaceMailer) NotifyIdle(_ context.Context, n lifecycle.Notice) error {
	if m.email == nil || !m.email.IsConfigured() {
		return nil
	}
	name := m.appName
	if name == "" {
		name = "OpenCTEM"
	}
	org := strings.NewReplacer("\r", "", "\n", "").Replace(n.Organization)
	esc := html.EscapeString
	date := func(t time.Time) string { return t.UTC().Format("2 January 2006") }
	signIn := esc(strings.TrimRight(m.baseURL, "/") + "/login")
	var subject, body string
	switch n.Stage {
	case lifecycledom.StageReminded:
		subject = fmt.Sprintf("[%s] Nobody has signed in to %s for 60 days", name, org)
		body = fmt.Sprintf(`<p>Nobody has signed in to <strong>%s</strong> for 60 days.</p>
<p>Sign in (%s) to keep it active. Otherwise it becomes read-only on %s and is scheduled for deletion on %s. Nothing is removed before then.</p>`,
			esc(org), signIn, date(n.ReadOnlyOn), date(n.DeletionDueOn))
	case lifecycledom.StageReadOnly:
		subject = fmt.Sprintf("[%s] %s is now read-only", name, org)
		body = fmt.Sprintf(`<p><strong>%s</strong> is now read-only: nobody signed in to it for 90 days. Your data is unchanged and can still be read and exported.</p>
<p>Sign in (%s) to make it active again. Otherwise it is scheduled for deletion on %s.</p>`,
			esc(org), signIn, date(n.DeletionDueOn))
	case lifecycledom.StageFinalWarning:
		subject = fmt.Sprintf("[%s] Last notice: %s is scheduled for deletion on %s", name, org, date(n.DeletionDueOn))
		body = fmt.Sprintf(`<p>This is the last notice for <strong>%s</strong>: it is scheduled for deletion on %s.</p>
<p>Sign in (%s) to keep it, or export what you need before then.</p>`,
			esc(org), date(n.DeletionDueOn), signIn)
	case lifecycledom.StageDeletionDue:
		subject = fmt.Sprintf("[%s] Idle Free organization %s is due for deletion", name, org)
		body = fmt.Sprintf(`<p>The Free organization <strong>%s</strong> has had no sign-in for 120 days; its owners were reminded and warned twice.</p>
<p>Review it in the console (Organizations), then delete it or exempt it. Nothing was deleted automatically.</p>`,
			esc(org))
	default:
		return nil
	}
	to := append([]string(nil), n.Recipients...)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", to, subject, body); err != nil {
			m.log.Warn("idle workspace email failed", "stage", string(n.Stage), "error", err)
		}
	}()
	return nil
}

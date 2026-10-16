package cirun

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fixedEmails []string

func (f fixedEmails) ActiveAdminEmails(context.Context, shared.ID) ([]string, error) { return f, nil }

type captureMailer struct{ ch chan [3]string }

func (m captureMailer) SendReport(_ context.Context, tenantID string, to []string, subject, body string) error {
	m.ch <- [3]string{tenantID + "|" + strings.Join(to, ","), subject, body}
	return nil
}

func TestAdminAlertEmailsAdministratorsOnlyWhenAsked(t *testing.T) {
	m := captureMailer{ch: make(chan [3]string, 2)}
	n := NewAdminAlerts(nil, nil, nil, nil)
	n.SetEmail(fixedEmails{"a@example.com", "b@example.com"}, m)
	tenant := shared.NewID()

	n.AlertAdmins(context.Background(), tenant, AdminAlert{Title: "quiet", Body: "no mail"})
	select {
	case got := <-m.ch:
		t.Fatalf("an alert that did not ask for e-mail sent one: %v", got)
	case <-time.After(50 * time.Millisecond):
	}

	n.AlertAdmins(context.Background(), tenant, AdminAlert{Title: "Renamed <x>", Body: "body & more", Email: true, EmailLink: "https://app.example.com/ci-cd?tab=setup"})
	select {
	case got := <-m.ch:
		if got[0] != tenant.String()+"|a@example.com,b@example.com" || got[1] != "Renamed <x>" {
			t.Fatalf("mail = %v", got)
		}
		if !strings.Contains(got[2], "body &amp; more") || !strings.Contains(got[2], `href="https://app.example.com/ci-cd?tab=setup"`) {
			t.Fatalf("body must be escaped and carry the link: %q", got[2])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no e-mail sent")
	}
}

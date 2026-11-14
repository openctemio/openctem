package notification

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// notifications.severity has CHECK (severity IN critical/high/medium/low/info)
// and the INSERT writes the field verbatim, so a caller that leaves Severity
// unset produced an empty string and the row was rejected. The pentest service never sets
// it: every campaign-member and pentest-finding in-app notification failed
// with chk_notification_severity and was dropped after a WARN.
func TestNewNotificationDefaultsSeverityToInfo(t *testing.T) {
	uid := shared.NewID()
	n := NewNotification(NotificationParams{
		TenantID:         shared.NewID(),
		Audience:         AudienceUser,
		AudienceID:       &uid,
		NotificationType: TypeCampaignMemberAdded,
		Title:            "added to campaign",
	})
	if n.Severity() != "info" {
		t.Fatalf("severity = %q, want info", n.Severity())
	}

	n = NewNotification(NotificationParams{TenantID: shared.NewID(), Audience: AudienceUser, AudienceID: &uid, Severity: "high"})
	if n.Severity() != "high" {
		t.Fatalf("an explicit severity was overwritten: %q", n.Severity())
	}
}

// A notification's time is the server's time of emission: the constructor
// takes no time from the caller, so a sensor- or client-reported time can
// never become the notification time.
func TestNewNotificationTimeIsServerNow(t *testing.T) {
	uid := shared.NewID()
	before := time.Now().Add(-time.Second)
	n := NewNotification(NotificationParams{TenantID: shared.NewID(), Audience: AudienceUser, AudienceID: &uid, NotificationType: TypeCoverageGap, Title: "gap"})
	after := time.Now().Add(time.Second)
	if n.CreatedAt().Before(before) || n.CreatedAt().After(after) {
		t.Fatalf("created at %v is not the emission time", n.CreatedAt())
	}
	if n.CreatedAt().Location() != time.UTC {
		t.Fatalf("created at is not UTC: %v", n.CreatedAt().Location())
	}
}

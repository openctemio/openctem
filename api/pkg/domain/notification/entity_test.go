package notification

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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

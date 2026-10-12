package exposure

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A campaign date is an RFC 3339 timestamp or a date alone (UTC: the start
// of the day for a start date, its last second for a due date). Anything
// else is refused with a validation error, never silently dropped; null
// (an empty string here) clears a date on update.
func TestCampaignDates_DateOnlyAcceptedGarbageRefused(t *testing.T) {
	ctx := context.Background()
	svc := newService(newFakeCampaignRepo(), nil)
	tid := shared.NewID().String()

	c, err := svc.CreateCampaign(ctx, CreateRemediationCampaignInput{
		TenantID: tid, Name: "dates", Priority: "high",
		StartDate: "2026-10-01", DueDate: "2026-10-31",
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("CreateCampaign with date-only values: %v", err)
	}
	if got, want := c.StartDate(), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC); got == nil || !got.Equal(want) {
		t.Fatalf("start_date = %v, want %v", got, want)
	}
	if got, want := c.DueDate(), time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC); got == nil || !got.Equal(want) {
		t.Fatalf("due_date = %v, want %v", got, want)
	}

	for _, bad := range []string{"31/10/2026", "2026-13-01", "tomorrow"} {
		_, err := svc.CreateCampaign(ctx, CreateRemediationCampaignInput{
			TenantID: tid, Name: "bad", Priority: "high", DueDate: bad,
		}, auditapp.AuditContext{})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("CreateCampaign due_date %q: %v, want a validation error", bad, err)
		}
	}

	ts := "2026-11-15T09:30:00Z"
	c, err = svc.UpdateCampaign(ctx, tid, c.ID().String(), UpdateRemediationCampaignInput{DueDate: &ts}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("UpdateCampaign RFC 3339: %v", err)
	}
	if got := c.DueDate(); got == nil || !got.Equal(time.Date(2026, 11, 15, 9, 30, 0, 0, time.UTC)) {
		t.Fatalf("due_date after update = %v", got)
	}
	bad := "15-11-2026"
	if _, err := svc.UpdateCampaign(ctx, tid, c.ID().String(), UpdateRemediationCampaignInput{StartDate: &bad}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("UpdateCampaign start_date %q: %v, want a validation error", bad, err)
	}
	clear := ""
	c, err = svc.UpdateCampaign(ctx, tid, c.ID().String(), UpdateRemediationCampaignInput{DueDate: &clear}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("UpdateCampaign clear: %v", err)
	}
	if c.DueDate() != nil {
		t.Fatalf("due_date not cleared: %v", c.DueDate())
	}
}

package exposure

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
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

	ts := "2026-10-15T09:30:00Z" // earlier: a deadline only tightens
	c, err = svc.UpdateCampaign(ctx, tid, c.ID().String(), UpdateRemediationCampaignInput{DueDate: &ts}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("UpdateCampaign RFC 3339: %v", err)
	}
	if got := c.DueDate(); got == nil || !got.Equal(time.Date(2026, 10, 15, 9, 30, 0, 0, time.UTC)) {
		t.Fatalf("due_date after update = %v", got)
	}
	bad := "15-11-2026"
	if _, err := svc.UpdateCampaign(ctx, tid, c.ID().String(), UpdateRemediationCampaignInput{StartDate: &bad}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("UpdateCampaign start_date %q: %v, want a validation error", bad, err)
	}
	// A campaign deadline only tightens: clearing it or moving it later is
	// refused; the same day or an earlier one is fine.
	clear := ""
	if _, err := svc.UpdateCampaign(ctx, tid, c.ID().String(), UpdateRemediationCampaignInput{DueDate: &clear}, auditapp.AuditContext{}); !errors.Is(err, remediation.ErrCampaignDeadlineOnlyTightens) {
		t.Fatalf("clearing the due date = %v, want ErrCampaignDeadlineOnlyTightens", err)
	}
	later := "2026-10-16"
	if _, err := svc.UpdateCampaign(ctx, tid, c.ID().String(), UpdateRemediationCampaignInput{DueDate: &later}, auditapp.AuditContext{}); !errors.Is(err, remediation.ErrCampaignDeadlineOnlyTightens) {
		t.Fatalf("a later due date = %v, want ErrCampaignDeadlineOnlyTightens", err)
	}
	sameDay, earlier := "2026-10-15", "2026-10-10"
	for _, d := range []string{sameDay, earlier} {
		if _, err := svc.UpdateCampaign(ctx, tid, c.ID().String(), UpdateRemediationCampaignInput{DueDate: &d}, auditapp.AuditContext{}); err != nil {
			t.Fatalf("due date %s: %v", d, err)
		}
	}
	// A campaign without a deadline may get one.
	open, err := svc.CreateCampaign(ctx, CreateRemediationCampaignInput{TenantID: tid, Name: "open", Priority: "high"}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateCampaign(ctx, tid, open.ID().String(), UpdateRemediationCampaignInput{DueDate: &later}, auditapp.AuditContext{}); err != nil {
		t.Fatalf("first due date: %v", err)
	}
}

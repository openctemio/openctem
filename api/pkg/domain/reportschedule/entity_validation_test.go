package reportschedule

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestNewReportSchedule_Validation(t *testing.T) {
	tid := shared.NewID()
	cases := []struct {
		name                string
		rtype, format, cron string
		wantErr             bool
	}{
		{"valid findings/pdf", "findings", "pdf", "0 9 * * *", false},
		{"valid hourly", "executive_summary", "pdf", "0 * * * *", false},
		{"valid every 6h", "executive_summary", "pdf", "0 */6 * * *", false},
		{"valid summary", "summary", "csv", "0 0 1 * *", false},
		{"sub-hourly every minute rejected", "findings", "pdf", "* * * * *", true},
		{"sub-hourly every 15m rejected", "findings", "pdf", "*/15 * * * *", true},
		{"sub-hourly every 30m rejected", "findings", "pdf", "0,30 * * * *", true},
		{"invalid cron syntax", "findings", "pdf", "not a cron expr", true},
		{"invalid cron field", "findings", "pdf", "99 99 * * *", true},
		{"unsupported report type", "haxxor", "pdf", "0 9 * * *", true},
		{"empty report type", "", "pdf", "0 9 * * *", true},
		{"empty cron", "findings", "pdf", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewReportSchedule(tid, "Sched", c.rtype, c.format, c.cron)
			if c.wantErr && err == nil {
				t.Fatalf("expected validation error for %+v", c)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr && err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected ErrValidation, got %v", err)
			}
		})
	}
}

func TestNewReportSchedule_NameLength(t *testing.T) {
	tid := shared.NewID()

	// A name at the cap is accepted; one over the cap is rejected.
	okName := strings.Repeat("a", maxNameLen)
	if _, err := NewReportSchedule(tid, okName, "findings", "pdf", "0 9 * * *"); err != nil {
		t.Fatalf("expected name of length %d to be accepted, got %v", maxNameLen, err)
	}

	longName := strings.Repeat("a", maxNameLen+1)
	_, err := NewReportSchedule(tid, longName, "findings", "pdf", "0 9 * * *")
	if err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation for over-long name, got %v", err)
	}
}

func TestReportSchedule_Update_Validation(t *testing.T) {
	tid := shared.NewID()
	base, err := NewReportSchedule(tid, "Sched", "findings", "pdf", "0 9 * * *")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Valid update (daily) succeeds.
	if err := base.Update("Renamed", "findings", "pdf", "0 8 * * *", "UTC"); err != nil {
		t.Fatalf("expected valid update to succeed, got %v", err)
	}

	// Over-long name on update is rejected.
	if err := base.Update(strings.Repeat("a", maxNameLen+1), "findings", "pdf", "0 8 * * *", "UTC"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation for over-long name on update, got %v", err)
	}

	// Sub-hourly cron on update is rejected.
	if err := base.Update("Sched", "findings", "pdf", "* * * * *", "UTC"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation for sub-hourly cron on update, got %v", err)
	}
}

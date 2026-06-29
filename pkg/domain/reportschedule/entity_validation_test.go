package reportschedule

import (
	"errors"
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
		{"valid executive_summary", "executive_summary", "pdf", "*/15 * * * *", false},
		{"valid summary", "summary", "csv", "0 0 1 * *", false},
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

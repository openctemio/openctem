package remediation

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A due date is a day: the campaign is overdue only once that day is over
// (UTC), whether the date was read back from the date column (midnight) or
// parsed as the day's last second.
func TestCampaignIsOverdue_AfterTheEndOfTheDueDay(t *testing.T) {
	c, err := NewCampaign(shared.NewID(), "c", CampaignPriorityHigh)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Activate(); err != nil {
		t.Fatal(err)
	}
	for _, due := range []time.Time{
		time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 15, 23, 59, 59, 0, time.UTC),
	} {
		c.SetDueDate(&due)
		if c.isOverdueAt(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)) {
			t.Errorf("due %s: overdue during the due day", due)
		}
		if !c.isOverdueAt(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("due %s: not overdue the next day", due)
		}
	}
}

func TestParseCampaignPriority(t *testing.T) {
	for _, ok := range []string{"critical", "high", "medium", "low"} {
		if _, err := ParseCampaignPriority(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"urgent", "", "HIGH"} {
		if _, err := ParseCampaignPriority(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

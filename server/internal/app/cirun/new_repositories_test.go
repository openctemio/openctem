package cirun

import (
	"testing"
	"time"
)

// Review finding: any user of the instance can create namespaces, and each
// new group raised a notice. At most newGroupNoticesPerHour go out per
// configuration and hour; the rest are counted and the first notice of the
// next hour says how many were held back. Configurations are independent.
func TestGroupNotices_BudgetPerConfiguration(t *testing.T) {
	var g groupNotices
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	sent := 0
	for i := 0; i < 40; i++ {
		if ok, _ := g.take("cfg-a", now.Add(time.Duration(i)*time.Second)); ok {
			sent++
		}
	}
	if sent != newGroupNoticesPerHour {
		t.Fatalf("sent %d notices in an hour, want %d", sent, newGroupNoticesPerHour)
	}
	if ok, _ := g.take("cfg-b", now); !ok {
		t.Fatal("another configuration's notice held back")
	}
	ok, held := g.take("cfg-a", now.Add(newGroupNoticeWindow+time.Minute))
	if !ok || held != 40-newGroupNoticesPerHour {
		t.Fatalf("next hour: send=%v held=%d, want true %d", ok, held, 40-newGroupNoticesPerHour)
	}
	if _, held := g.take("cfg-a", now.Add(newGroupNoticeWindow+2*time.Minute)); held != 0 {
		t.Fatalf("held count reported twice: %d", held)
	}
}

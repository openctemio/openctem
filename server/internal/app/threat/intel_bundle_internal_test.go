package threat

import (
	"testing"
	"time"
)

func TestNewerData(t *testing.T) {
	d := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	if !storedAsOf(map[string]any{MetaIntelAsOf: d.Format(time.RFC3339)}).Equal(d) {
		t.Fatal("stored date not read")
	}
	if !newerData("kev", d.Add(time.Second), d) || newerData("kev", d, d) || newerData("kev", d.Add(-time.Hour), d) {
		t.Fatal("KEV compares releases by time")
	}
	if newerData("epss", d.Add(5*time.Hour), d) || !newerData("epss", d.Add(24*time.Hour), d) {
		t.Fatal("EPSS compares scores by day")
	}
	if !newerData("kev", d, time.Time{}) {
		t.Fatal("nothing held: any date is newer")
	}
}

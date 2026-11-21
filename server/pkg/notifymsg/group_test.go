package notifymsg

import (
	"fmt"
	"strings"
	"testing"
)

func groupInput(n int, level Level, loc string) GroupInput {
	in := GroupInput{
		EventType: "finding_priority_escalated", Level: level, Locale: loc, Organization: "Example Corp",
		URL:   "https://console.example.com/findings?notification_group_id=0190a5b4-0000-7000-8000-000000000001",
		Count: n, Severities: map[string]int{"high": n},
	}
	for i := range n {
		asset := "http://203.0.113.10"
		if i%3 == 2 {
			asset = "app.example.com"
		}
		epss := 0.42
		in.Entries = append(in.Entries, GroupEntry{
			Severity: "high", Reason: "EPSS above the threshold",
			Facts: &Facts{Title: fmt.Sprintf("PHP 8.1.%d argument injection", i), CVE: fmt.Sprintf("CVE-2024-%04d", 4500+i),
				AssetName: asset, AssetType: "service", EPSS: &epss},
		})
	}
	return in
}

func TestBuildGroup_HeadlineCountAndTarget(t *testing.T) {
	c := BuildGroup(groupInput(6, LevelStandard, "en"))
	if c.Headline != "6 findings raised to High" {
		t.Fatalf("headline %q", c.Headline)
	}
	if c.Severity != "high" || c.Action.Label != "Open the list" || !strings.Contains(c.Action.URL, "notification_group_id=") {
		t.Fatalf("card %+v", c)
	}
	vi := BuildGroup(groupInput(6, LevelStandard, "vi"))
	if vi.Headline != "6 phát hiện được nâng lên mức Cao" {
		t.Fatalf("vi headline %q", vi.Headline)
	}
	mixed := groupInput(3, LevelStandard, "en")
	mixed.Severities = map[string]int{"critical": 1, "high": 2}
	mc := BuildGroup(mixed)
	if mc.Headline != "3 findings raised in priority" || mc.Severity != "critical" || mc.What != "1 Critical, 2 High" {
		t.Fatalf("mixed %q %q %q", mc.Headline, mc.Severity, mc.What)
	}
	other := groupInput(2, LevelStandard, "en")
	other.EventType = "some_future_event"
	if h := BuildGroup(other).Headline; h != "2 alerts: Some future event" {
		t.Fatalf("fallback headline %q", h)
	}
}

func TestBuildGroup_ByAssetAtMostTenLines(t *testing.T) {
	c := BuildGroup(groupInput(40, LevelStandard, "en"))
	if len(c.Sections) != 2 || c.Sections[0].Title != "http://203.0.113.10 (service)" || c.Sections[1].Title != "app.example.com (service)" {
		t.Fatalf("sections %+v", c.Sections)
	}
	n := 0
	for _, s := range c.Sections {
		n += len(s.Items)
	}
	if n != MaxGroupLines || c.More != 30 {
		t.Fatalf("lines %d more %d", n, c.More)
	}
	line := c.Sections[0].Items[0]
	if line != "CVE-2024-4500: PHP 8.1.0 argument injection, High, Likely to be exploited (EPSS 42%)" &&
		!strings.HasPrefix(line, "CVE-2024-4500: PHP 8.1.0 argument injection, High, ") {
		t.Fatalf("line %q", line)
	}
	text := c.Text()
	if !strings.Contains(text, "+30 more") || strings.Count(text, "\n- ") != MaxGroupLines {
		t.Fatalf("text:\n%s", text)
	}
}

// Minimal channels get no asset or finding names, only the count.
func TestBuildGroup_MinimalHasNoNames(t *testing.T) {
	c := BuildGroup(groupInput(6, LevelMinimal, "en"))
	if len(c.Sections) != 0 || strings.Contains(c.Text(), "203.0.113.10") || strings.Contains(c.Text(), "CVE-") {
		t.Fatalf("minimal leaks names:\n%s", c.Text())
	}
	if c.Headline != "6 findings raised to High" {
		t.Fatalf("headline %q", c.Headline)
	}
}

// No internal ID reaches the text; long values are capped.
func TestBuildGroup_NoIDsAndCapped(t *testing.T) {
	in := groupInput(1, LevelStandard, "en")
	in.Entries[0].Facts.Title = "see 0190a5b4-0000-7000-8000-000000000001 " + strings.Repeat("x", 500)
	in.Entries[0].Reason = strings.Repeat("r", 500)
	c := BuildGroup(in)
	line := c.Sections[0].Items[0]
	if strings.Contains(line, "0190a5b4") {
		t.Fatalf("id in line %q", line)
	}
	if n := len([]rune(line)); n > maxGroupWhatRunes+maxGroupReasonRunes+20 {
		t.Fatalf("line %d runes", n)
	}
}

func TestApplyTemplateCount(t *testing.T) {
	c := BuildGroup(groupInput(6, LevelStandard, "en"))
	out, ok := ApplyTemplateCount(c, "{count} raised at {organization}", 6)
	if !ok || len(out.Custom) != 1 || out.Custom[0] != "6 raised at Example Corp" {
		t.Fatalf("template %+v", out.Custom)
	}
	if !strings.Contains(out.Text(), "\n- ") {
		t.Fatal("template layout dropped the listed items")
	}
}

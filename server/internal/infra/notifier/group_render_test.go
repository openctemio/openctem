package notifier

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/notifymsg"
)

// sampleGroupCard is a grouped message of n findings over two assets.
func sampleGroupCard(n int) notifymsg.Card {
	in := notifymsg.GroupInput{
		EventType: "finding_priority_escalated", Level: notifymsg.LevelStandard, Locale: "en",
		Organization: "Example Corp", URL: goldenBase + "/findings?notification_group_id=0190a5b4-0000-7000-8000-000000000001",
		Count: n, Severities: map[string]int{"high": n},
	}
	for i := range n {
		asset := "http://203.0.113.10"
		if i%2 == 1 {
			asset = "app.example.com"
		}
		in.Entries = append(in.Entries, notifymsg.GroupEntry{Severity: "high", Reason: "Known to be exploited",
			Facts: &notifymsg.Facts{Title: fmt.Sprintf("PHP 8.1.%d argument injection", i), CVE: fmt.Sprintf("CVE-2024-%04d", 4500+i),
				AssetName: asset, AssetType: "service"}})
	}
	return notifymsg.BuildGroup(in)
}

// A grouped message stays within Telegram's 4096 characters even when every
// value is at its cap and full of characters the HTML escaping expands.
func TestTelegramCard_FitsTheLimit(t *testing.T) {
	in := notifymsg.GroupInput{
		EventType: "finding_priority_escalated", Level: notifymsg.LevelFull, Locale: "en",
		Organization: strings.Repeat("&<>", 200), URL: goldenBase + "/findings", Count: 5000,
		Severities: map[string]int{"high": 5000},
	}
	for i := range 10 {
		in.Entries = append(in.Entries, notifymsg.GroupEntry{Severity: "high", Reason: strings.Repeat("<&>", 100),
			Facts: &notifymsg.Facts{Title: strings.Repeat("&<>\"", 100), AssetName: fmt.Sprintf("%d%s", i, strings.Repeat("<>", 100))}})
	}
	card := notifymsg.BuildGroup(in)
	text := telegramCard(card)
	if n := len([]rune(text)); n > telegramMaxText {
		t.Fatalf("telegram text %d characters, limit %d", n, telegramMaxText)
	}
	if strings.Count(text, "<b>") != strings.Count(text, "</b>") {
		t.Fatal("a line was cut inside its markup")
	}
}

// Slack and Teams carry the asset headings and the items; the webhook
// payload has them as sections.
func TestGroupCard_EveryRenderer(t *testing.T) {
	card := sampleGroupCard(14)
	blocks, _ := json.Marshal(slackCardBlocks(card))
	if !strings.Contains(string(blocks), "*http[:]//203.0.113.10 (service)*") || !strings.Contains(string(blocks), "+4 more") {
		t.Fatalf("slack blocks: %s", blocks)
	}
	teams, _ := json.Marshal(teamsCardBody(card, "attention"))
	if !strings.Contains(string(teams), "app.example.com (service)") || !strings.Contains(string(teams), "Bolder") {
		t.Fatalf("teams body: %s", teams)
	}
	n := newCardNotification(&card)
	if len(n.Sections) != 2 || n.More != 4 || n.Headline != "14 findings raised to High" {
		t.Fatalf("webhook notification %+v", n)
	}
}

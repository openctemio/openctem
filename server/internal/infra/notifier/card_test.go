package notifier

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/notifymsg"
)

var updateGolden = flag.Bool("update", false, "rewrite the renderer golden files")

const goldenBase = "https://ctem.example.com"

// cardMessage is what the outbox hands a client: the card plus its plain
// text form, cleaned the way the factory's client cleans it.
func cardMessage(card notifymsg.Card) Message {
	return Message{
		Title: card.Headline, Body: card.Text(), Severity: card.Severity, URL: card.Action.URL,
		EventType: card.EventType, EventVersion: 1, IdempotencyKey: "outbox-test", Card: &card,
	}.Cleaned()
}

func goldenCards() map[string]notifymsg.Card {
	exposure := notifymsg.Build(notifymsg.SampleInput("new_exposure", notifymsg.LevelStandard, "en", goldenBase))
	finding := notifymsg.Build(notifymsg.SampleInput("new_finding", notifymsg.LevelFull, "vi", goldenBase))
	minimal := notifymsg.Build(notifymsg.SampleInput("new_exposure", notifymsg.LevelMinimal, "en", goldenBase))
	templated, _ := notifymsg.ApplyTemplate(exposure, "{asset} needs a look: {what}\nOwner team: platform")
	return map[string]notifymsg.Card{
		"exposure_standard_en": exposure,
		"finding_full_vi":      finding,
		"exposure_minimal_en":  minimal,
		"exposure_template_en": templated,
	}
}

// renderAll renders one card with every provider, as each one sends it.
func renderAll(t *testing.T, card notifymsg.Card) map[string]string {
	t.Helper()
	msg := cardMessage(card)
	js := func(v any) string {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return string(b) + "\n"
	}
	wh := (&WebhookClient{}).buildPayload(msg)
	wh.Timestamp, wh.OccurredAt = "<now>", "<now>"
	sp := (&SplunkClient{sourcetype: "openctem:notification"}).buildEvent(msg)
	sp.Time = 0
	ec := &EmailClient{product: "OpenCTEM"}
	html, err := ec.buildHTMLEmail(msg)
	if err != nil {
		t.Fatal(err)
	}
	html = regexp.MustCompile(`at \d{4}-\d\d-\d\d \d\d:\d\d:\d\d [A-Z+\-0-9]+`).ReplaceAllString(html, "at <now>")
	return map[string]string{
		"telegram":   js((&TelegramClient{chatID: "42"}).buildMessage(msg)),
		"slack":      js((&SlackClient{}).buildMessage(msg)),
		"teams":      js((&TeamsClient{}).buildMessage(msg)),
		"webhook":    js(wh),
		"splunk":     js(sp),
		"email.txt":  ec.buildTextEmail(msg),
		"email.html": html,
	}
}

func TestCardRenderersMatchGoldenFiles(t *testing.T) {
	for name, card := range goldenCards() {
		for provider, got := range renderAll(t, card) {
			path := filepath.Join("testdata", "golden", name+"."+provider)
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %v (run go test -run Golden -update)", path, err)
			}
			if string(want) != got {
				t.Errorf("%s differs from the golden file:\n%s", path, got)
			}
		}
	}
}

// The message the owner saw: title three times, severity three times, a
// raw defanged link next to the button. A card says each thing once and the
// link only lives in the button.
func TestCardSaysEachThingOnce(t *testing.T) {
	card := goldenCards()["exposure_standard_en"]
	text := (&TelegramClient{chatID: "1"}).buildMessage(cardMessage(card))
	if strings.Count(text.Text, "New exposure") != 1 || strings.Count(text.Text, "High") != 1 {
		t.Fatalf("repeats:\n%s", text.Text)
	}
	if strings.Contains(text.Text, "http") || strings.Contains(text.Text, "{") {
		t.Fatalf("link or raw brace in text:\n%s", text.Text)
	}
	if text.ReplyMarkup == nil || text.ReplyMarkup.InlineKeyboard[0][0].Text != "Open exposure" {
		t.Fatal("no action button")
	}
	email := (&EmailClient{}).buildTextEmail(cardMessage(card))
	if strings.Count(email, goldenBase) != 1 {
		t.Fatalf("e-mail text must carry the link exactly once:\n%s", email)
	}
}

var uuidRE = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// No internal UUID in visible text: only the action link carries one.
func TestCardVisibleTextHasNoInternalIDs(t *testing.T) {
	in := notifymsg.SampleInput("sensor.offline", notifymsg.LevelFull, "en", goldenBase)
	in.ProducerTitle = "Sensor 0192f3c4-1111-7abc-8def-0123456789ab went offline"
	in.URL = goldenBase + "/sensors/0192f3c4-1111-7abc-8def-0123456789ab?org=0192f3c4-2222-7abc-8def-0123456789ab"
	card := notifymsg.Build(in)
	tg := (&TelegramClient{}).buildMessage(cardMessage(card))
	if uuidRE.MatchString(tg.Text) {
		t.Fatalf("visible text carries an id:\n%s", tg.Text)
	}
	if !uuidRE.MatchString(tg.ReplyMarkup.InlineKeyboard[0][0].URL) {
		t.Fatal("the button lost the link")
	}
}

// hostile is text a scan target can put in an asset name or title.
const hostile = "<b>x</b></a><a href=\"https://evil.example/p\">click</a> <!channel> <@U123> [here](https://evil.example) *b* _i_ \u202egnp.exe {asset} &amp;"

func hostileCard(t *testing.T, template string) notifymsg.Card {
	t.Helper()
	in := notifymsg.SampleInput("new_exposure", notifymsg.LevelFull, "en", goldenBase)
	in.Facts.AssetName, in.Facts.Title, in.Facts.Description = hostile, hostile, hostile
	in.Organization = hostile
	card := notifymsg.Build(in)
	if template != "" {
		var ok bool
		if card, ok = notifymsg.ApplyTemplate(card, template); !ok {
			t.Fatalf("template refused: %q", template)
		}
	}
	return card
}

func TestCardRenderersEscapeInjection(t *testing.T) {
	for name, tpl := range map[string]string{
		"default layout": "",
		// The template author's literal text is escaped like any value.
		"template": "<i>{asset}</i> <!here> [x](https://evil.example) {what}",
	} {
		t.Run(name, func(t *testing.T) {
			card := hostileCard(t, tpl)
			msg := cardMessage(card)

			tg := (&TelegramClient{}).buildMessage(msg).Text
			for _, tag := range regexp.MustCompile(`<[^>]*>`).FindAllString(tg, -1) {
				if tag != "<b>" && tag != "</b>" {
					t.Errorf("telegram: markup from untrusted text %q in\n%s", tag, tg)
				}
			}
			if strings.Contains(tg, "https://") || strings.Contains(tg, "\u202e") {
				t.Errorf("telegram: live link or bidi override:\n%s", tg)
			}

			sl, _ := json.Marshal((&SlackClient{}).buildMessage(msg))
			var slack slackMessage
			_ = json.Unmarshal(sl, &slack)
			texts := []string{slack.Text}
			for _, b := range slack.Attachments[0].Blocks {
				if b.Text != nil {
					texts = append(texts, b.Text.Text)
				}
				for _, e := range b.Elements {
					if el, ok := e.(map[string]any); ok {
						if s, ok := el["text"].(string); ok {
							texts = append(texts, s)
						}
					}
				}
			}
			for _, s := range texts {
				if strings.ContainsAny(s, "<>") || strings.Contains(s, "https://") {
					t.Errorf("slack: control characters or live link in %q", s)
				}
			}

			tm, _ := json.Marshal((&TeamsClient{}).buildMessage(msg))
			if regexp.MustCompile(`[^\\]\[(here|x)\]\(`).Match(tm) || strings.Contains(string(tm), "https://evil") {
				t.Errorf("teams: markdown link survived: %s", tm)
			}

			html, err := (&EmailClient{}).buildHTMLEmail(msg)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(html, `<a href="https://evil`) || strings.Contains(html, "<b>x</b>") || strings.Contains(html, "<i>") {
				t.Errorf("email: markup from untrusted text survived")
			}

			wh, _ := json.Marshal((&WebhookClient{}).buildPayload(msg))
			var back map[string]any
			if err := json.Unmarshal(wh, &back); err != nil {
				t.Fatalf("webhook: payload is not valid JSON: %v", err)
			}
		})
	}
}

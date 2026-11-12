package notifier

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/server/pkg/notifymsg"
	"github.com/openctemio/openctem/server/pkg/safetext"
)

// Card rendering: every provider lays out a notifymsg.Card the same way.
// The headline once, the severity once (a line, plus the provider's marker:
// an emoji in chat, a color bar or badge), the labeled lines in a fixed
// order, and one action: a button where the provider has one. The link
// never appears in the text, so it is never defanged or duplicated.
//
// Every value and every label is escaped for its target. Values in chat
// text also have their URLs defanged: an asset name or a title can come
// from a scan target, and the only link of a message is its action.

// Block Kit and Adaptive Card element types used by the card renderers.
const (
	slackPlainText = "plain_text"
	slackMrkdwn    = "mrkdwn"
	slackSection   = "section"
	teamsTextBlock = "TextBlock"
)

// chatValue is the untrusted-value transform shared by the chat renderers
// before their own escaping.
func chatValue(s string) string { return safetext.Defang(s) }

// telegramCard renders card as Telegram HTML text.
func telegramCard(card notifymsg.Card) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s</b>", GetSeverityEmoji(card.Severity), telegramText(card.Headline))
	for _, l := range card.Lines() {
		b.WriteByte('\n')
		if l.Label != "" {
			fmt.Fprintf(&b, "<b>%s:</b> ", telegramText(l.Label))
		}
		b.WriteString(telegramText(l.Value))
	}
	return b.String()
}

// slackCardBlocks renders card as Block Kit blocks.
func slackCardBlocks(card notifymsg.Card) []slackBlock {
	blocks := make([]slackBlock, 0, 4)
	blocks = append(blocks, slackBlock{
		Type: "header",
		Text: &slackTextBlock{
			Type:  slackPlainText,
			Text:  safetext.Truncate(GetSeverityEmoji(card.Severity)+" "+chatValue(card.Headline), 150),
			Emoji: true,
		},
	})
	var org string
	var lines []string
	for _, l := range card.Lines() {
		if l.Key == "organization" {
			org = l.Value
			continue
		}
		v := slackEscape(chatValue(l.Value))
		if l.Label != "" {
			v = "*" + slackEscape(l.Label) + ":* " + v
		}
		lines = append(lines, v)
	}
	if len(lines) > 0 {
		blocks = append(blocks, slackBlock{Type: slackSection,
			Text: &slackTextBlock{Type: slackMrkdwn, Text: safetext.Truncate(strings.Join(lines, "\n"), 3000)}})
	}
	if org != "" {
		blocks = append(blocks, slackBlock{Type: "context", Elements: []any{
			slackElement{Type: slackMrkdwn, Text: slackEscape(chatValue(org))},
		}})
	}
	if card.Action.URL != "" {
		blocks = append(blocks, slackBlock{Type: "actions", Elements: []any{
			slackButton{Type: "button", Text: &slackTextBlock{Type: slackPlainText, Text: safetext.Truncate(card.Action.Label, 75)}, URL: card.Action.URL},
		}})
	}
	return blocks
}

// slackCardFallback is the plain text a Slack notification (phone banner)
// shows. Slack renders it as mrkdwn, so it is escaped like the blocks.
func slackCardFallback(card notifymsg.Card) string {
	return slackEscape(chatValue(card.Headline + " (" + card.SeverityText() + ")"))
}

// teamsCardBody renders card as Adaptive Card body elements.
func teamsCardBody(card notifymsg.Card, style string) []teamsBody {
	body := []teamsBody{{
		Type:  "Container",
		Style: style,
		Items: []teamsBody{{
			Type: teamsTextBlock, Text: GetSeverityEmoji(card.Severity) + " " + teamsEscape(chatValue(card.Headline)),
			Weight: "Bolder", Size: "Medium", Wrap: true,
		}},
	}}
	lines := card.Lines()
	facts := make([]teamsFact, 0, len(lines))
	var texts []teamsBody
	for _, l := range lines {
		if l.Label == "" {
			texts = append(texts, teamsBody{Type: teamsTextBlock, Text: teamsEscape(chatValue(l.Value)), Wrap: true})
			continue
		}
		facts = append(facts, teamsFact{Title: teamsEscape(l.Label), Value: teamsEscape(chatValue(l.Value))})
	}
	if len(facts) > 0 {
		body = append(body, teamsBody{Type: "FactSet", Facts: facts})
	}
	return append(body, texts...)
}

// cardNotification is the "notification" object of the webhook and Splunk
// payloads (schema openctem.notification/v1): the card for machines, with
// stable keys. Empty values are omitted; no internal IDs besides the link.
type cardNotification struct {
	Schema       string            `json:"schema"`
	DetailLevel  string            `json:"detail_level"`
	Locale       string            `json:"locale"`
	Headline     string            `json:"headline"`
	Severity     string            `json:"severity"`
	Organization string            `json:"organization,omitempty"`
	Subject      *cardSubject      `json:"subject,omitempty"`
	What         string            `json:"what,omitempty"`
	Why          string            `json:"why,omitempty"`
	NextStep     string            `json:"next_step,omitempty"`
	Description  string            `json:"description,omitempty"`
	Items        []string          `json:"items,omitempty"`
	More         int               `json:"more,omitempty"`
	Text         string            `json:"text"`
	Action       *cardNotifyAction `json:"action,omitempty"`
}

type cardSubject struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type cardNotifyAction struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// NotificationSchema names the webhook "notification" object version.
const NotificationSchema = "openctem.notification/v1"

func newCardNotification(card *notifymsg.Card) *cardNotification {
	if card == nil {
		return nil
	}
	n := &cardNotification{
		Schema:       NotificationSchema,
		DetailLevel:  string(card.Level),
		Locale:       card.Locale,
		Headline:     card.Headline,
		Severity:     card.Severity,
		Organization: card.Organization,
		What:         card.What,
		Why:          card.Why,
		NextStep:     card.NextStep,
		Description:  card.Description,
		Items:        card.Items,
		More:         card.More,
		Text:         card.Text(),
	}
	if card.Subject.Name != "" {
		n.Subject = &cardSubject{Name: card.Subject.Name, Type: card.Subject.Type}
	}
	if card.Action.URL != "" {
		n.Action = &cardNotifyAction{Label: card.Action.Label, URL: card.Action.URL}
	}
	return n
}

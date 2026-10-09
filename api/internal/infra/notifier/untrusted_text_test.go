package notifier

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// attackerText is finding/exposure content an attacker controls (a scanned
// page title, a crafted package name, a sensor report). It tries to ping the
// whole channel, mention a user, and plant a disguised link.
const attackerText = "Reset needed <!channel> <!here> <@U0123ABCD> " +
	"<https://evil.example/login|Click here to re-authenticate> " +
	"[Re-authenticate](https://evil.example/teams) & more"

func attackerMessage() Message {
	return Message{
		Title:      "SQLi " + attackerText,
		Body:       attackerText,
		Severity:   SeverityHigh,
		URL:        "https://app.openctem.test/findings/123",
		Fields:     map[string]string{"Asset <!channel>": attackerText},
		FooterText: "Sent via OpenCTEM.io",
	}
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// slackTexts returns every text string Slack will render as mrkdwn.
func slackMrkdwnTexts(m slackMessage) []string {
	var out []string
	for _, a := range m.Attachments {
		for _, b := range a.Blocks {
			if b.Text != nil && b.Text.Type == "mrkdwn" {
				out = append(out, b.Text.Text)
			}
			for _, f := range b.Fields {
				if f.Type == "mrkdwn" {
					out = append(out, f.Text)
				}
			}
			for _, e := range b.Elements {
				if el, ok := e.(slackElement); ok && el.Type == "mrkdwn" {
					out = append(out, el.Text)
				}
			}
		}
	}
	return out
}

func TestSlack_UntrustedTextCannotMentionOrLink(t *testing.T) {
	c := &SlackClient{}
	msg := c.buildMessage(attackerMessage())
	texts := slackMrkdwnTexts(msg)
	require.NotEmpty(t, texts)
	for _, txt := range texts {
		// Slack's control sequences are <...>; with < and > escaped none of
		// <!channel>, <!here>, <@U..> or <url|label> can form.
		require.NotContains(t, txt, "<", "unescaped < in Slack mrkdwn: %q", txt)
		require.NotContains(t, txt, ">", "unescaped > in Slack mrkdwn: %q", txt)
		require.NotContains(t, strings.ReplaceAll(txt, "&amp;", ""), "& ", "unescaped & in Slack mrkdwn: %q", txt)
	}
	joined := strings.Join(texts, "\n")
	require.Contains(t, joined, "&lt;!channel&gt;", "the text is still shown, escaped")
}

func TestSlack_OwnLinkStillWorks(t *testing.T) {
	c := &SlackClient{}
	out := marshal(t, c.buildMessage(attackerMessage()))
	// Our link is a real Block Kit button: a plain_text label and a url field.
	require.Contains(t, out, `"type":"button"`)
	require.Contains(t, out, `"url":"https://app.openctem.test/findings/123"`)
	require.Contains(t, out, `"text":{"type":"plain_text","text":"View Details"`)
}

// Teams Adaptive Card TextBlocks and FactSet values render markdown, so
// [label](url) becomes a clickable, disguised link.
func TestTeams_UntrustedTextCannotFormMarkdownLinks(t *testing.T) {
	c := &TeamsClient{}
	out := marshal(t, c.buildMessage(attackerMessage()))
	require.NotContains(t, out, "[Re-authenticate](https://evil.example/teams)",
		"attacker markdown link reaches Teams unescaped")
	require.Contains(t, out, `"url":"https://app.openctem.test/findings/123"`, "our own action link still works")
}

// Telegram messages are HTML: untrusted text is escaped and its URLs
// defanged, so it forms no tag, link or entity. A title with characters
// legacy Markdown could not escape inside an entity (an underscore in a
// rule name) no longer makes Telegram refuse the message.
func TestTelegram_UntrustedTextCannotFormLinksOrTags(t *testing.T) {
	c := &TelegramClient{chatID: "1"}
	m := attackerMessage()
	m.Title = `generic_api_key <a href="https://evil.example">x</a>`
	req := c.buildMessage(m)
	require.Equal(t, "HTML", req.ParseMode)
	require.NotContains(t, req.Text, `<a href=`)
	require.Contains(t, req.Text, `&lt;a href=&#34;https[:]//evil.example&#34;&gt;`)
	require.Contains(t, req.Text, "generic_api_key")
	require.NotContains(t, req.Text, "https://evil")
	require.Equal(t, "https://app.openctem.test/findings/123", req.ReplyMarkup.InlineKeyboard[0][0].URL)
}

// The email notifier renders through html/template, so markup in finding
// content is escaped. This pins that behavior.
func TestEmail_UntrustedTextIsHTMLEscaped(t *testing.T) {
	c := &EmailClient{config: EmailConfig{}}
	m := attackerMessage()
	m.Body = `<a href="https://evil.example">Click</a><script>alert(1)</script>`
	html, err := c.buildHTMLEmail(m)
	require.NoError(t, err)
	require.NotContains(t, html, `<a href="https://evil.example">`)
	require.NotContains(t, html, `<script>alert(1)`)
	require.Contains(t, html, `href="https://app.openctem.test/findings/123"`)
}

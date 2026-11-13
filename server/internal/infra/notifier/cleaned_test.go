package notifier

import (
	"context"
	"strings"
	"testing"
)

type recordingClient struct{ got Message }

func (r *recordingClient) Send(_ context.Context, msg Message) (*SendResult, error) {
	r.got = msg
	return &SendResult{Success: true}, nil
}
func (r *recordingClient) TestConnection(context.Context) (*SendResult, error) { return nil, nil }
func (r *recordingClient) Provider() string                                    { return "rec" }

// A title a hostile target serves: an RLO override (Trojan Source), a
// zero-width space, a NUL and a terminal escape.
const hostileTitle = "Critical on invoice\u202Etxt.exe\u200B\x00\x1b[2J"

func TestCleaningClient_StripsBidiAndControlFromEveryField(t *testing.T) {
	rec := &recordingClient{}
	c := cleaningClient{Client: rec}
	_, err := c.Send(context.Background(), Message{
		Title:       hostileTitle,
		Body:        "body " + hostileTitle,
		Fields:      map[string]string{"Asset\u202E": hostileTitle},
		FooterText:  hostileTitle,
		Attachments: []Attachment{{Title: hostileTitle, Text: hostileTitle}},
		URL:         "https://app.openctem.test/findings/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	all := []string{rec.got.Title, rec.got.Body, rec.got.FooterText, rec.got.Attachments[0].Title, rec.got.Attachments[0].Text}
	for k, v := range rec.got.Fields {
		all = append(all, k, v)
	}
	for _, s := range all {
		if strings.ContainsAny(s, "\u202E\u200B\x00\x1b") {
			t.Errorf("field kept a control/bidi character: %q", s)
		}
	}
	if rec.got.Title != "Critical on invoicetxt.exe[2J" {
		t.Errorf("title = %q", rec.got.Title)
	}
	if rec.got.URL != "https://app.openctem.test/findings/1" {
		t.Errorf("URL changed: %q", rec.got.URL)
	}
}

func TestCleaningClient_CapsLength(t *testing.T) {
	rec := &recordingClient{}
	_, _ = cleaningClient{Client: rec}.Send(context.Background(), Message{Title: strings.Repeat("a", 5000)})
	if n := len([]rune(rec.got.Title)); n != maxNotificationTitleRunes {
		t.Fatalf("title is %d runes, want %d", n, maxNotificationTitleRunes)
	}
}

func TestFactory_ReturnsCleaningClient(t *testing.T) {
	c, err := (&ClientFactory{}).CreateClient(Config{
		Provider:      ProviderWebhook,
		WebhookURL:    "https://hooks.example.com/x",
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if _, ok := c.(cleaningClient); !ok {
		t.Fatalf("factory returned %T, want cleaningClient", c)
	}
	if c.Provider() != "webhook" {
		t.Fatalf("provider = %q", c.Provider())
	}
}

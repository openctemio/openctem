package evidence

import (
	"encoding/base64"
	"strings"
	"testing"
)

// PRIVACY (research/292): every item the platform stores has its e-mail
// addresses masked, whichever path built it (ingest, a retest, a person's
// upload), with or without secrets in it, and none reaches the secret store.
// Body match ranges stay on their (masked) text.
func TestMaskMasksEmailAddressesEverywhere(t *testing.T) {
	body := "<p>Mail jane.doe@example.com or ops@example.org</p>"
	s, e := strings.Index(body, "jane"), strings.Index(body, "jane")+len("jane.doe@example.com")
	b64 := base64.StdEncoding.EncodeToString([]byte("reply-to: bob@example.net"))
	cases := map[string]Item{
		"no secret": {Kind: KindHTTPExchange, Extracted: []string{"jane.doe@example.com"},
			HTTP: &HTTP{
				Request:  &HTTPRequest{Method: "GET", URL: "https://h.example.com/r?u=jane%40example.com", Headers: []Header{{Name: "From", Value: "jane.doe@example.com"}}},
				Response: &HTTPResponse{Status: 200, Body: body, Headers: []Header{{Name: "X-Contact", Value: "ops@example.org"}}},
			},
			Match: []Match{{Location: "response", Part: "body", Start: &s, End: &e}},
		},
		"with a secret": {Kind: KindHTTPExchange,
			HTTP: &HTTP{
				Request:  &HTTPRequest{Method: "GET", URL: "https://h.example.com/", Headers: []Header{{Name: "Authorization", Value: "Bearer abcdefghijklmnop123"}}},
				Response: &HTTPResponse{Status: 200, Body: "token abcdefghijklmnop123 for jane.doe@example.com"},
			}},
		"base64 text body": {Kind: KindHTTPExchange, HTTP: &HTTP{Response: &HTTPResponse{Status: 200, Body: b64, BodyEncoding: "base64"}}},
		"raw text":         {Kind: KindRawText, Text: "author: Jane <jane.doe@example.com>", Label: "x@example.com"},
		"command":          {Kind: KindCommandOutput, Command: "mail -s hi jane.doe@example.com", Text: "sent to jane.doe@example.com"},
	}
	for name, in := range cases {
		it, ok := Normalize(in)
		if !ok {
			t.Fatalf("%s: normalize dropped it", name)
		}
		masked, secrets := Mask(it)
		all := allText(t, masked)
		for _, addr := range []string{"jane.doe@", "ops@", "bob@", "jane%40", "x@example"} {
			if strings.Contains(all, addr) {
				t.Errorf("%s: %q left in %s", name, addr, all)
			}
		}
		for _, sec := range secrets {
			if strings.Contains(sec.Value, "@example") {
				t.Errorf("%s: an address reached the secret store: %+v", name, sec)
			}
		}
		if name == "no secret" {
			m := masked.Match[0]
			if got := masked.HTTP.Response.Body[*m.Start:*m.End]; got != "j***@example.com" {
				t.Errorf("match points at %q", got)
			}
			if !strings.Contains(all, "o***@example.org") {
				t.Errorf("domain not kept: %s", all)
			}
		}
		if name == "with a secret" && strings.Contains(all, "abcdefghijklmnop123") {
			t.Errorf("secret left: %s", all)
		}
		// Idempotent (an item without secrets: secret placeholders are
		// renumbered by a second pass).
		if again, _ := Mask(masked); len(secrets) == 0 && allText(t, again) != all {
			t.Errorf("%s: second mask changed the item", name)
		}
	}
}

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

// PRIVACY (research/292): an item stored before Mask masked addresses gets
// exactly that masking from MaskItemEmails: every free string and header
// value, a base64 body that is text (decoded, as Mask stores it), match
// ranges moved onto their masked text. A binary body, version strings and
// digests stay; an item without an address does not change; a second pass
// changes nothing.
func TestMaskItemEmailsOnAStoredItem(t *testing.T) {
	body := "<p>Mail Jane.Doe@Example.COM</p><b>lib@1.2.3 image@sha256:abcdef</b>"
	s, e := strings.Index(body, "<b>"), strings.Index(body, "</b>")
	textB64 := base64.StdEncoding.EncodeToString([]byte("reply-to: bob@example.net"))
	binB64 := base64.StdEncoding.EncodeToString([]byte{0, 1, 2, '@', 'x', '.', 'c', 'o', 'm', 0xff})
	bs, be := 0, 4
	it := Item{
		Kind: KindHTTPExchange, Label: "x@example.com", Extracted: []string{"ops@example.org", "lib@1.2.3"},
		Text: "jane%40example.com", Command: "mail jane.doe@example.com", File: &File{Path: "a@b.example.com/x", Snippet: "owner = jane@example.com"},
		HTTP: &HTTP{
			Request: &HTTPRequest{Method: "POST", URL: "https://h.example.com/r?u=jane%40example.com&v=1",
				Headers: []Header{{Name: "From", Value: "jane.doe@example.com"}}, Body: textB64, BodyEncoding: "base64"},
			Response: &HTTPResponse{Status: 200, Body: body, Headers: []Header{{Name: "X-Contact", Value: "ops@example.org"}}},
		},
		Match: []Match{{Location: "response", Part: "body", Start: &s, End: &e}, {Location: "request", Part: "body", Start: &bs, End: &be}},
	}
	before := it.HTTP.Response.Body[s:e]
	if !MaskItemEmails(&it) {
		t.Fatal("nothing changed")
	}
	all := allText(t, it)
	for _, addr := range []string{"Jane.Doe@", "jane.doe@", "ops@", "bob@", "jane%40", "x@example", "jane@"} {
		if strings.Contains(all, addr) {
			t.Errorf("%q left in %s", addr, all)
		}
	}
	for _, kept := range []string{"***@Example.COM", "***%40example.com", "lib@1.2.3", "image@sha256:abcdef", "a@b.example.com/x"} {
		if !strings.Contains(all, kept) {
			t.Errorf("%q missing from %s", kept, all)
		}
	}
	if q := it.HTTP.Request; q.BodyEncoding != "" || q.Body != "reply-to: ***@example.net" {
		t.Errorf("text base64 body = %q (%q)", q.Body, q.BodyEncoding)
	}
	if m := it.Match[0]; it.HTTP.Response.Body[*m.Start:*m.End] != before {
		t.Errorf("match points at %q, want %q", it.HTTP.Response.Body[*m.Start:*m.End], before)
	}
	if m := it.Match[1]; m.Start != nil || m.End != nil {
		t.Error("a decoded body kept the offsets of its encoded text")
	}
	if MaskItemEmails(&it) {
		t.Error("second pass changed the item")
	}

	bin := Item{Kind: KindHTTPExchange, HTTP: &HTTP{Response: &HTTPResponse{Status: 200, Body: binB64, BodyEncoding: "base64"}}}
	plainB64 := base64.StdEncoding.EncodeToString([]byte("no address here"))
	plain := Item{Kind: KindHTTPExchange, HTTP: &HTTP{Response: &HTTPResponse{Status: 200, Body: plainB64, BodyEncoding: "base64"}}}
	for name, x := range map[string]*Item{"binary": &bin, "text without address": &plain} {
		was := allText(t, x)
		if MaskItemEmails(x) || allText(t, x) != was {
			t.Errorf("%s base64 body changed: %s", name, allText(t, x))
		}
	}
}

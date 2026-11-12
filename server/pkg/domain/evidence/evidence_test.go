package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	jwt     = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	session = "s3ss10n-abcdef-123456"
	apiKey  = "AKIAIOSFODNN7EXAMPLE"
)

func exchange() Item {
	req := "POST /api/login?access_token=qtok-998877&page=2 HTTP/1.1\r\n" +
		"Host: shop.example.com\r\n" +
		"Authorization: Bearer " + jwt + "\r\n" +
		"Cookie: theme=dark; sid=" + session + "\r\n" +
		"X-Api-Key: " + apiKey + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"user=alice&password=hunter2-long"
	resp := "HTTP/1.1 200 OK\r\nSet-Cookie: sid=" + session + "; Path=/; HttpOnly\r\nContent-Type: application/json\r\n\r\n" +
		`{"ok":true,"echo":"` + session + `","client_secret":"cs-77665544","version":"7.1.0"}`
	items := FromToolProperties(map[string]any{
		"request": req, "response": resp, "matcher_name": "word-1",
		"extracted_results": []any{"7.1.0"},
		"curl_command":      "curl -H 'Cookie: sid=" + session + "' -H 'Authorization: Bearer " + jwt + "' 'https://shop.example.com/api/login?access_token=qtok-998877'",
	}, "https://shop.example.com/api/login?access_token=qtok-998877&page=2", "nuclei test")
	if len(items) != 2 {
		panic("want exchange + curl")
	}
	return items[0]
}

func allText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMaskRemovesEverySecretEverywhere(t *testing.T) {
	it, ok := Normalize(exchange())
	if !ok {
		t.Fatal("normalize dropped the exchange")
	}
	masked, secrets := Mask(it)
	out := allText(t, masked)
	for _, s := range []string{jwt, session, apiKey, "qtok-998877", "hunter2-long", "cs-77665544"} {
		if strings.Contains(out, s) {
			t.Errorf("masked item still contains %q:\n%s", s, out)
		}
	}
	found := map[string]bool{}
	for _, s := range secrets {
		found[s.Value] = true
		if !IsPlaceholder(s.Placeholder) {
			t.Errorf("bad placeholder %q", s.Placeholder)
		}
	}
	for _, s := range []string{jwt, session, apiKey, "qtok-998877", "hunter2-long", "cs-77665544"} {
		if !found[s] {
			t.Errorf("secret %q was not kept for reveal", s)
		}
	}
	// The auth scheme and the cookie names stay readable.
	q := masked.HTTP.Request
	var auth, cookie string
	for _, h := range q.Headers {
		switch h.Name {
		case "Authorization":
			auth = h.Value
		case "Cookie":
			cookie = h.Value
		}
	}
	if !strings.HasPrefix(auth, "Bearer «secret:authorization#") {
		t.Errorf("Authorization = %q, want the scheme kept", auth)
	}
	// Every cookie value is masked (any of them can be a session); the names stay.
	if !strings.HasPrefix(cookie, "theme=«secret:cookie#") || !strings.Contains(cookie, "; sid=«secret:cookie#") {
		t.Errorf("Cookie = %q, want names kept and values masked", cookie)
	}
	if !strings.Contains(q.URL, "page=2") || strings.Contains(q.URL, "qtok") {
		t.Errorf("URL = %q", q.URL)
	}
	// The same value gets the same placeholder (the echo in the response).
	var sessionPH string
	for _, s := range secrets {
		if s.Value == session {
			sessionPH = s.Placeholder
		}
	}
	if sessionPH == "" || strings.Count(out, sessionPH) < 3 {
		t.Errorf("the session value should map to one placeholder in request, Set-Cookie and body echo:\n%s", out)
	}
}

func TestMaskKeepsMatchOnItsText(t *testing.T) {
	it, _ := Normalize(exchange())
	masked, _ := Mask(it)
	if len(masked.Match) != 1 || masked.Match[0].Start == nil {
		t.Fatalf("match = %+v", masked.Match)
	}
	m := masked.Match[0]
	if got := masked.HTTP.Response.Body[*m.Start:*m.End]; got != "7.1.0" {
		t.Errorf("match points at %q after masking, want 7.1.0", got)
	}
}

func TestMaskHonoursToolMarkedSpans(t *testing.T) {
	s, e := 4, 12
	it := Item{Kind: KindRawText, Text: "pin=93817264 ok", Sensitive: []Sensitive{{Pointer: "/text", Start: &s, End: &e, Kind: "pin"}}}
	it, _ = Normalize(it)
	masked, secrets := Mask(it)
	if strings.Contains(masked.Text, "93817264") || len(secrets) != 1 || secrets[0].Kind != "pin" {
		t.Fatalf("text %q secrets %+v", masked.Text, secrets)
	}
	if masked.Sensitive != nil {
		t.Error("sensitive spans must not be stored")
	}
}

func TestMaskShortSensitiveHeaderIsHiddenWithoutPlaintext(t *testing.T) {
	it, _ := Normalize(Item{Kind: KindHTTPExchange, HTTP: &HTTP{Request: &HTTPRequest{URL: "https://h/", Headers: []Header{{Name: "X-Auth-Token", Value: "abc"}}}}})
	masked, _ := Mask(it)
	if v := masked.HTTP.Request.Headers[0].Value; v == "abc" {
		t.Errorf("short token kept: %q", v)
	}
}

func TestMaskBase64TextBody(t *testing.T) {
	it, _ := Normalize(Item{Kind: KindHTTPExchange, HTTP: &HTTP{Response: &HTTPResponse{
		Status: 200, Body: "eyJ0b2tlbiI6ICJzdXBlci1zZWNyZXQtdmFsdWUifQ==", BodyEncoding: "base64",
	}}})
	masked, _ := Mask(it)
	if strings.Contains(allText(t, masked), "super-secret-value") || masked.HTTP.Response.BodyEncoding != "" {
		t.Errorf("base64 text body not decoded and masked: %+v", masked.HTTP.Response)
	}
}

func TestNormalizeCapsAndWindowsAroundMatch(t *testing.T) {
	body := strings.Repeat("a", 200<<10) + "NEEDLE" + strings.Repeat("b", 200<<10)
	start, end := 200<<10, 200<<10+6
	hs := make([]Header, 150)
	for i := range hs {
		hs[i] = Header{Name: "X-H", Value: strings.Repeat("v", 20<<10)}
	}
	it, ok := Normalize(Item{Kind: KindHTTPExchange, HTTP: &HTTP{Response: &HTTPResponse{Status: 200, Body: body, Headers: hs}},
		Match: []Match{{Location: "response", Part: "body", Start: &start, End: &end}}, Extracted: make([]string, 50)})
	if !ok {
		t.Fatal("dropped")
	}
	r := it.HTTP.Response
	if len(r.Body) > MaxBodyBytes+64 || !r.BodyTruncated || !it.Truncated {
		t.Errorf("body %d bytes, truncated=%v", len(r.Body), r.BodyTruncated)
	}
	if r.BodySize != len(body) {
		t.Errorf("body_size = %d, want the original %d", r.BodySize, len(body))
	}
	if len(r.Headers) != MaxHeaders || len(r.Headers[0].Value) > MaxHeaderValue+32 {
		t.Errorf("headers %d, first %d bytes", len(r.Headers), len(r.Headers[0].Value))
	}
	if len(it.Extracted) != MaxExtracted {
		t.Errorf("extracted = %d", len(it.Extracted))
	}
	if len(it.Match) != 1 || r.Body[*it.Match[0].Start:*it.Match[0].End] != "NEEDLE" {
		t.Fatalf("match not kept on the windowed body: %+v", it.Match)
	}
	b, _ := json.Marshal(it)
	if len(b) > MaxItemBytes*2 {
		t.Errorf("item %d bytes", len(b))
	}
}

func TestNormalizeDropsBadMatchesAndControlChars(t *testing.T) {
	s, e := 5, 999
	it, _ := Normalize(Item{Kind: KindRawText, Label: "a\x00b\nc\x1b", Text: "x\x00y",
		Match: []Match{{Location: "response", Part: "body", Start: &s, End: &e}, {Location: "x", Part: "body"}}})
	if it.Label != "ab c" || it.Text != "xy" || len(it.Match) != 0 {
		t.Errorf("%+v", it)
	}
}

func TestDecodeKeepsUnknownKindAsText(t *testing.T) {
	it, ok := Decode(json.RawMessage(`{"kind":"grpc_call","service":"a.B","payload":{"x":1}}`))
	if !ok || it.Kind != "grpc_call" || !strings.Contains(it.Text, `"service": "a.B"`) {
		t.Fatalf("%v %+v", ok, it)
	}
	if _, ok := Decode(json.RawMessage(`{"kind":"<script>"}`)); ok {
		t.Error("hostile kind accepted")
	}
	if _, ok := Decode(json.RawMessage(`not json`)); ok {
		t.Error("junk accepted")
	}
	list := DecodeList(json.RawMessage(`[{"kind":"raw_text","text":"a"},{"kind":"BAD KIND"},{"kind":"curl","text":"curl x"}]`), 5)
	if len(list) != 2 {
		t.Errorf("list = %+v", list)
	}
}

func TestParseRawRequestAbsoluteURL(t *testing.T) {
	q := ParseRawRequest("GET /wp-admin/js/theme.js HTTP/1.1\r\nHost: shop.example.com\r\nAccept: */*\r\n\r\n", "https://shop.example.com/wp-admin/js/theme.js")
	if q.Method != "GET" || q.URL != "https://shop.example.com/wp-admin/js/theme.js" || q.HTTPVersion != "HTTP/1.1" || len(q.Headers) != 2 {
		t.Errorf("%+v", q)
	}
	r := ParseRawResponse("HTTP/1.0 404 File not found\r\nServer: x\r\n\r\nnope")
	if r.Status != 404 || r.Reason != "File not found" || r.Body != "nope" {
		t.Errorf("%+v", r)
	}
}

func TestCurlQuotesEverything(t *testing.T) {
	it := Item{Kind: KindHTTPExchange, HTTP: &HTTP{Request: &HTTPRequest{Method: "POST", URL: "https://h/a?x=1'$(id)",
		Headers: []Header{{Name: "Host", Value: "h"}, {Name: "X-A", Value: "it's"}}, Body: "a'b"}}}
	got := Curl(it)
	want := `curl -sS -i -X 'POST' -H 'X-A: it'\''s' --data-binary 'a'\''b' 'https://h/a?x=1'\''$(id)'`
	if got != want {
		t.Errorf("curl\n got %s\nwant %s", got, want)
	}
}

func TestHashIsStable(t *testing.T) {
	it, _ := Normalize(exchange())
	again, _ := Normalize(exchange())
	if Hash(it) == "" || Hash(it) != Hash(again) {
		t.Error("hash not stable")
	}
}

func TestMaskLeavesToolMaskedValuesAlone(t *testing.T) {
	it, _ := Normalize(Item{Kind: KindHTTPExchange, HTTP: &HTTP{Request: &HTTPRequest{URL: "https://h/", Headers: []Header{
		{Name: "Authorization", Value: "***"}, {Name: "Cookie", Value: "***"}, {Name: "X-Api-Key", Value: "[REDACTED]"},
	}}}})
	masked, secrets := Mask(it)
	if len(secrets) != 0 {
		t.Fatalf("a value the tool already masked became a revealable secret: %+v", secrets)
	}
	if v := masked.HTTP.Request.Headers[0].Value; v != "***" {
		t.Errorf("Authorization = %q, want the tool mask kept", v)
	}
}

func TestCredentialShapes(t *testing.T) {
	got := CredentialShapes("token: {{token}}\nkey AKIAABCDEFGHIJKLMNOP and AKIAABCDEFGHIJKLMNOQ ghp_abcdefghijklmnopqrstuvwxyz")
	if len(got) != 2 || got[0] != "aws_key" || got[1] != "token" {
		t.Fatalf("kinds %v", got)
	}
	if got := CredentialShapes("Authorization: Bearer {{token}}\npassword: {{pass}}"); len(got) != 0 {
		t.Fatalf("names flagged: %v", got)
	}
}

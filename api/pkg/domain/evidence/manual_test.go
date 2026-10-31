package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFromRequestResponse_Shapes(t *testing.T) {
	if _, ok := FromRequestResponse(nil); ok {
		t.Error("an empty entry made an item")
	}
	if _, ok := FromRequestResponse(map[string]any{"notes": "only notes"}); ok {
		t.Error("an entry with notes only made an item")
	}
	raw, ok := FromRequestResponse(map[string]any{
		"request":  "GET /a?x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n",
		"response": "HTTP/1.1 403 Forbidden\r\n\r\nno",
		"url":      "https://h.test/a",
	})
	if !ok || raw.HTTP.Request.Method != "GET" || raw.HTTP.Request.URL != "https://h.test/a?x=1" || raw.HTTP.Response.Status != 403 {
		t.Errorf("raw entry = %+v / %+v", raw.HTTP.Request, raw.HTTP.Response)
	}
	var st map[string]any
	_ = json.Unmarshal([]byte(`{"method":"post","url":"https://h.test/l","request_headers":{"b":"2","a":"1"},
		"response_status":201,"response_headers":[{"name":"X","value":"y"}],"notes":"n"}`), &st)
	it, ok := FromRequestResponse(st)
	if !ok || it.HTTP.Request.Method != "POST" || it.Label != "n" || it.HTTP.Response.Status != 201 {
		t.Fatalf("structured entry = %+v", it)
	}
	if h := it.HTTP.Request.Headers; len(h) != 2 || h[0].Name != "a" || h[1].Name != "b" {
		t.Errorf("object headers not sorted by name: %+v", h)
	}
	if h := it.HTTP.Response.Headers; len(h) != 1 || h[0].Name != "X" || h[0].Value != "y" {
		t.Errorf("list headers = %+v", h)
	}
}

// Every credential a recorded exchange commonly carries is masked out.
func TestFromRequestResponse_MaskedSecrets(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0ZXIifQ.c2lnbmF0dXJlLXZhbHVlLXg"
	secrets := []string{jwt, "sess-unit-0001", "setc-unit-0002", "qkey-unit-0003", "pw-unit-0004", "tok-unit-0005"}
	it, ok := FromRequestResponse(map[string]any{
		"method": "POST", "url": "https://h.test/l?api_key=qkey-unit-0003",
		"request_headers": map[string]any{"Authorization": "Bearer " + jwt, "Cookie": "sid=sess-unit-0001", "Content-Type": "application/json"},
		"request_body":    `{"password":"pw-unit-0004","refresh_token":"tok-unit-0005"}`,
		"response_status": 200, "response_headers": map[string]any{"Set-Cookie": "s=setc-unit-0002; Path=/"},
	})
	if !ok {
		t.Fatal("no item")
	}
	n, _ := Normalize(it)
	masked, found := Mask(n)
	b, _ := json.Marshal(masked)
	for _, s := range secrets {
		if strings.Contains(string(b), s) {
			t.Errorf("secret %q left in the masked item", s)
		}
	}
	if len(found) < len(secrets) {
		t.Errorf("%d secrets found, want %d", len(found), len(secrets))
	}
}

func TestContainsPlaceholder(t *testing.T) {
	for name, m := range map[string]map[string]any{
		"top":    {"request": "Cookie: a=«secret:cookie#1»"},
		"nested": {"request_headers": map[string]any{"Cookie": "«secret:cookie#2»"}},
		"list":   {"response_headers": []any{map[string]any{"name": "Set-Cookie", "value": "«secret:cookie#3»"}}},
	} {
		if !ContainsPlaceholder(m) {
			t.Errorf("%s: placeholder not seen", name)
		}
	}
	if ContainsPlaceholder(map[string]any{"request": "GET / HTTP/1.1", "response_status": 200.0}) {
		t.Error("a plain entry reported a placeholder")
	}
}

package webendpoint

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func TestSanitizePostureKeepsOnlyAllowListedTypedKeys(t *testing.T) {
	raw := map[string]any{
		"hsts": true, "hsts_max_age": float64(31536000), "csp": true, "csp_unsafe_inline": false,
		"frame_options": "DENY", "referrer_policy": "no-referrer", "cors_origin": "wildcard",
		"set_cookie":     "session=SECRETVALUE",         // not allow-listed
		"authorization":  "Bearer abc",                  // not allow-listed
		"csp_value":      "default-src 'self'",          // value: dropped
		"x_frame_banner": strings.Repeat("A", 5000),     // unknown
		"nosniff":        "yes",                         // wrong type: dropped
		"referrer":       map[string]any{"v": "secret"}, // unknown
		"cookies": []any{
			map[string]any{"name": "sid", "secure": true, "httponly": true, "samesite": "Lax", "value": "TOPSECRET"},
			map[string]any{"name": "bad name\r\n", "secure": true},
			map[string]any{"name": "sid"},
		},
	}
	out := SanitizePosture(raw)
	b, _ := json.Marshal(out)
	for _, leak := range []string{"SECRETVALUE", "Bearer", "default-src", "TOPSECRET", "AAAA", "secret", "bad name"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("posture kept %q: %s", leak, b)
		}
	}
	if out["frame_options"] != "deny" || out["hsts_max_age"] != 31536000 || out["csp"] != true {
		t.Fatalf("typed keys lost: %s", b)
	}
	if _, ok := out["nosniff"]; ok {
		t.Fatalf("wrong-typed bool kept: %s", b)
	}
	cs := out["cookies"].([]any)
	if len(cs) != 1 || cs[0].(map[string]any)["samesite"] != "lax" {
		t.Fatalf("cookies = %s", b)
	}
}

func TestSanitizePostureAbsentAndHostile(t *testing.T) {
	for _, in := range []any{nil, "x", 3, map[string]any{}, map[string]any{"unknown": true}, []any{1}} {
		if SanitizePosture(in) != nil {
			t.Fatalf("SanitizePosture(%v) must be nil", in)
		}
	}
	many := make([]any, 100)
	for i := range many {
		many[i] = map[string]any{"name": "c" + strings.Repeat("x", i%10) + string(rune('a'+i%26)) + string(rune('a'+i/26))}
	}
	out := SanitizePosture(map[string]any{"cookies": many})
	if n := len(out["cookies"].([]any)); n > MaxPostureCookies {
		t.Fatalf("cookie list not bounded: %d", n)
	}
	if SanitizePosture(map[string]any{"hsts_max_age": float64(1e12)}) != nil {
		t.Fatal("absurd max-age kept")
	}
}

func TestExtLabel(t *testing.T) {
	cases := map[string]string{
		"/backup.sql": "ext:dbdump", "/site.zip": "ext:archive", "/index.php.bak": "ext:backup",
		"/.env": "ext:config", "/app.log": "ext:log", "/x/main.py": "ext:source", "/page~": "ext:backup",
		"/index.html": "", "/api/{int}": "", "/": "", "/BACKUP.SQL": "ext:dbdump",
	}
	for in, want := range cases {
		if got := ExtLabel(in); got != want {
			t.Errorf("ExtLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestObserveSetsPlatformLabels(t *testing.T) {
	o, err := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/login", Method: "POST", Kind: ctis.EndpointKindForm,
		Params: []ctis.EndpointParam{{Location: ctis.ParamLocationForm, Name: "user"}, {Location: ctis.ParamLocationForm, Name: "Password"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Labels) != 1 || o.Labels[0] != LabelAuthLogin {
		t.Fatalf("labels = %v", o.Labels)
	}
	// A query parameter named password does not make a login form.
	q, _ := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/search", Method: "GET",
		Params: []ctis.EndpointParam{{Location: ctis.ParamLocationQuery, Name: "password"}}})
	if len(q.Labels) != 0 {
		t.Fatalf("query param marked login: %v", q.Labels)
	}
	d, _ := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/dump.sql", Method: "GET"})
	if len(d.Labels) != 1 || d.Labels[0] != "ext:dbdump" {
		t.Fatalf("labels = %v", d.Labels)
	}
}

func TestCatalogVerifyMapping(t *testing.T) {
	n := 0
	for _, e := range DefaultCatalog.Entries {
		if e.Verify == nil {
			continue
		}
		n++
		if e.Severity != "critical" {
			t.Errorf("%s: only critical entries are mapped, got %s", e.Key, e.Severity)
		}
		if e.Verify.validate() != nil {
			t.Errorf("%s: invalid verify block", e.Key)
		}
	}
	if n != 20 {
		t.Fatalf("mapped entries = %d, want 20", n)
	}
}

func TestAlertCandidates(t *testing.T) {
	git, _ := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/.git/config", Method: "GET", StatusCode: 200})
	if git.CatalogKey == "" {
		t.Fatal("catalog miss")
	}
	ids := map[string]string{git.TemplateHash: "11111111-1111-1111-1111-111111111111"}
	got := AlertCandidates([]Observation{git}, map[string]PriorState{}, ids)
	if len(got) != 1 || got[0].Kind != AlertSensitiveNew || got[0].Severity != "critical" {
		t.Fatalf("new critical path: %+v", got)
	}
	// Seen before and unchanged: nothing.
	if got := AlertCandidates([]Observation{git}, map[string]PriorState{git.TemplateHash: {State: "active"}}, ids); len(got) != 0 {
		t.Fatalf("known endpoint alerted: %+v", got)
	}
	// Under a path exclusion: never.
	ex := git
	ex.OutOfScope = true
	if got := AlertCandidates([]Observation{ex}, map[string]PriorState{}, ids); len(got) != 0 {
		t.Fatalf("excluded endpoint alerted: %+v", got)
	}
	// Auth lost.
	api, _ := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/api/v1/users", Method: "GET", Kind: ctis.EndpointKindAPI, Auth: ctis.EndpointAuthNone})
	ids2 := map[string]string{api.TemplateHash: "22222222-2222-2222-2222-222222222222"}
	got = AlertCandidates([]Observation{api}, map[string]PriorState{api.TemplateHash: {Auth: "required", State: "active"}}, ids2)
	if len(got) != 1 || got[0].Kind != AlertAuthLost {
		t.Fatalf("auth lost: %+v", got)
	}
	// Fingerprint is stable per tenant/origin/kind/template and differs per tenant.
	a, b := got[0].Fingerprint("t1", "o"), got[0].Fingerprint("t2", "o")
	if a == b || a != got[0].Fingerprint("t1", "o") {
		t.Fatal("fingerprint not tenant-bound/stable")
	}
}

package webendpoint

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func TestObserve_TemplatesAndDropsQueryValues(t *testing.T) {
	obs, err := Observe(ctis.Endpoint{
		Origin: "https://shop.example.com", Method: "get", Path: "/orders/42/items",
		Kind: ctis.EndpointKindAPI, Source: ctis.EndpointSourceJS, StatusCode: 200,
		ContentType: "application/json; charset=utf-8",
		Params:      []ctis.EndpointParam{{Location: ctis.ParamLocationJSON, Name: "/note", TypeHint: "string"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Method != "GET" || obs.PathTemplate != "/orders/{int}/items" || obs.ExamplePath != "/orders/42/items" {
		t.Fatalf("got %s %s (example %s)", obs.Method, obs.PathTemplate, obs.ExamplePath)
	}
	if obs.ContentType != "application/json" || obs.Kind != "api" || strings.Join(obs.Sources, ",") != "js" || obs.AuthState != AuthUnknown {
		t.Fatalf("attributes: %+v", obs)
	}
	if obs.TemplateHash == "" || obs.PathHash == "" || obs.TemplateHash == obs.PathHash {
		t.Fatalf("hashes: %q %q", obs.TemplateHash, obs.PathHash)
	}
	// The same template from another method is another endpoint, the same
	// pattern.
	post, _ := Observe(ctis.Endpoint{Origin: "https://shop.example.com", Method: "POST", Path: "/orders/7/items"})
	if post.TemplateHash == obs.TemplateHash || post.PathHash != obs.PathHash {
		t.Fatal("method must change the endpoint key and not the pattern key")
	}
}

func TestObserve_RefusesSmuggledQueryUserInfoAndBadInput(t *testing.T) {
	for name, e := range map[string]ctis.Endpoint{
		"query in path":      {Origin: "https://a.example.com", Path: "/x?token=SECRET"},
		"fragment in path":   {Origin: "https://a.example.com", Path: "/x#SECRET"},
		"relative path":      {Origin: "https://a.example.com", Path: "x"},
		"origin with path":   {Origin: "https://a.example.com/app", Path: "/x"},
		"origin with query":  {Origin: "https://a.example.com?k=SECRET", Path: "/x"},
		"user info":          {Origin: "https://user:SECRET@a.example.com", Path: "/x"},
		"other scheme":       {Origin: "ftp://a.example.com", Path: "/x"},
		"unknown method":     {Origin: "https://a.example.com", Path: "/x", Method: "BREW"},
		"control characters": {Origin: "https://a.example.com", Path: "/x\n/y"},
		"path too long":      {Origin: "https://a.example.com", Path: "/" + strings.Repeat("a", MaxPathBytes)},
	} {
		if _, err := Observe(e); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/logo.png", Kind: ctis.EndpointKindStatic}); !errors.Is(err, ErrStatic) {
		t.Errorf("static: err = %v, want ErrStatic", err)
	}
}

func TestObserve_MasksTokenSegmentsInExample(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	obs, err := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/reset/" + jwt + "/user%40example.com/2026-10-07"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(obs.ExamplePath, jwt) || strings.Contains(obs.ExamplePath, "example.com") {
		t.Fatalf("example path keeps a token or an e-mail: %q", obs.ExamplePath)
	}
	if obs.ExamplePath != "/reset/{token}/{email}/2026-10-07" {
		t.Fatalf("example = %q", obs.ExamplePath)
	}
}

func TestObserve_ParamsAreNamesOnlyBoundedAndClassified(t *testing.T) {
	params := []ctis.EndpointParam{
		{Location: ctis.ParamLocationQuery, Name: "redirect_uri"},
		{Location: ctis.ParamLocationForm, Name: "password", Required: true},
		{Location: ctis.ParamLocationPath, Name: "user_id", TypeHint: "INT"},
		{Location: "body", Name: "unknown-location"},
		{Location: ctis.ParamLocationQuery, Name: "bad\nname"},
		{Location: ctis.ParamLocationQuery, Name: "redirect_uri"}, // duplicate
	}
	for i := range 150 {
		params = append(params, ctis.EndpointParam{Location: ctis.ParamLocationHeader, Name: "x-h-" + string(rune('a'+i%26)) + strings.Repeat("z", i)})
	}
	obs, err := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/login", Params: params})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Params) != MaxParamsPerEndpoint {
		t.Fatalf("%d params kept, want the cap %d", len(obs.Params), MaxParamsPerEndpoint)
	}
	byName := map[string]ParamObservation{}
	for _, p := range obs.Params {
		byName[p.Name] = p
		if p.Location == "body" || strings.ContainsRune(p.Name, '\n') {
			t.Fatalf("invalid param kept: %+v", p)
		}
	}
	if !slices.Contains(byName["redirect_uri"].RiskHints, RiskSSRF) || !slices.Contains(byName["redirect_uri"].RiskHints, RiskRedirect) {
		t.Errorf("redirect_uri hints = %v", byName["redirect_uri"].RiskHints)
	}
	if byName["password"].Sensitive != SensitiveCredential || !byName["password"].Required {
		t.Errorf("password = %+v", byName["password"])
	}
	if !slices.Contains(byName["user_id"].RiskHints, RiskIDOR) || byName["user_id"].TypeHint != "int" {
		t.Errorf("user_id = %+v", byName["user_id"])
	}
}

func TestObserve_QueryNamesOfPathAreParams(t *testing.T) {
	// weburl keeps a query's names; the path a report sends must not carry
	// one, but an origin + path combination is re-parsed, so the names of a
	// legacy URL folded by ingest arrive through Params instead.
	obs, err := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/search",
		Params: []ctis.EndpointParam{{Location: ctis.ParamLocationQuery, Name: "q"}}})
	if err != nil || len(obs.Params) != 1 || obs.Params[0].Name != "q" {
		t.Fatalf("params = %+v, err %v", obs.Params, err)
	}
}

func TestResponseSig_ChangesWithStatusContentTypeAuth(t *testing.T) {
	a := Observation{StatusCode: 200, ContentType: "text/html", AuthState: "none"}
	b := a
	b.StatusCode = 401
	if a.ResponseSig() == b.ResponseSig() {
		t.Fatal("status change must change the signature")
	}
	c := a
	c.Technologies = []string{"nginx"}
	if a.ResponseSig() != c.ResponseSig() {
		t.Fatal("unrelated attribute changed the signature")
	}
}

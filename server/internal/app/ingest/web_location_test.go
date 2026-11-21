package ingest

import (
	"testing"

	ctis "github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/weburl"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestWebLocationUpdate_ResolvesRefThenTemplate(t *testing.T) {
	origin := shared.NewID()
	plan := &endpointPlan{
		origins: map[string]string{"o1": "https://a.test"},
		refs:    map[string]planRef{"ep1": {originRef: "o1", templateHash: weburl.PathHash("POST", "/login")}},
	}
	refs := plan.resolveRefs(map[string]shared.ID{"o1": origin})

	// endpoint_ref wins: the origin is the persisted asset.
	f := &ctis.Finding{Web: &ctis.WebLocation{URL: "https://a.test/other", Method: "POST", EndpointRef: "ep1",
		Parameter: &ctis.WebParameter{Location: ctis.ParamLocationQuery, Name: "q=secret"}, StatusCode: 500}}
	u, ok := webLocationUpdate(refs, "fp", f)
	if !ok || u.OriginAssetID != origin.String() || u.EndpointHash != weburl.PathHash("POST", "/login") ||
		u.Method != "POST" || u.ParamName != "q" || u.ParamLocation != "query" || u.StatusCode != 500 {
		t.Fatalf("got %+v", u)
	}

	// An unknown ref falls back to the method and the URL's template.
	f = &ctis.Finding{Web: &ctis.WebLocation{URL: "https://a.test/items/9", Method: "GET", EndpointRef: "nope"}}
	u, ok = webLocationUpdate(refs, "fp", f)
	if !ok || u.EndpointHash != weburl.PathHash("GET", "/items/{int}") || u.AnyMethodHash != weburl.PathHash("ANY", "/items/{int}") ||
		u.OriginAssetID != origin.String() {
		t.Fatalf("fallback got %+v", u)
	}

	// No endpoint can be named: the rest of the location is still kept.
	u, ok = webLocationUpdate(nil, "fp", &ctis.Finding{Web: &ctis.WebLocation{Method: "get"}})
	if !ok || u.Method != "GET" || u.EndpointHash != "" {
		t.Fatalf("got %+v", u)
	}

	// A finding without a web location stores nothing.
	if _, ok := webLocationUpdate(refs, "fp", &ctis.Finding{}); ok {
		t.Fatal("a finding with no web location produced an update")
	}
}

package webendpoint

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/ctis/v2"
)

func guessEndpoint(t *testing.T, source ctis.EndpointSource, evidence string) ctis.Endpoint {
	t.Helper()
	raw := `{"origin":"https://app.example.com","path":"/index.php.bak","method":"GET","status_code":200,"source":"` + string(source) + `"`
	if evidence != "" {
		raw += `,"extensions":{"io.openctem":{"response":` + evidence + `}}`
	}
	raw += `}`
	var e ctis.Endpoint
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func bind(t *testing.T, capability string, e ctis.Endpoint) (Observation, error) {
	t.Helper()
	obs, err := Observe(e)
	if err != nil {
		t.Fatal(err)
	}
	return obs, BindSource(&obs, capability, e)
}

// A path discovery job's endpoints are guess whatever the tool claims, and
// carry the evidence.
func TestBindSourceGuessFromCapability(t *testing.T) {
	for _, claim := range []ctis.EndpointSource{"probe", "crawl", "", "guess"} {
		e := guessEndpoint(t, claim, `{"size":48213,"hash":"0123456789abcdef"}`)
		obs, err := bind(t, "enumerate.web_paths@1", e)
		if err != nil {
			t.Fatalf("claim %q: %v", claim, err)
		}
		if !slices.Equal(obs.Sources, []string{SourceGuess}) {
			t.Fatalf("claim %q: sources %v, want [guess]", claim, obs.Sources)
		}
		if obs.Evidence == nil || obs.Evidence.Size != 48213 || obs.Evidence.Hash != "0123456789abcdef" {
			t.Fatalf("claim %q: evidence %+v", claim, obs.Evidence)
		}
	}
}

// A guessed endpoint without valid evidence is refused.
func TestBindSourceGuessNeedsEvidence(t *testing.T) {
	for name, ev := range map[string]string{
		"none":           "",
		"not an object":  `"x"`,
		"no hash":        `{"size":10}`,
		"no size":        `{"hash":"0123456789abcdef"}`,
		"short hash":     `{"size":10,"hash":"0123"}`,
		"upper hash":     `{"size":10,"hash":"0123456789ABCDEF"}`,
		"non-hex hash":   `{"size":10,"hash":"0123456789abcdeg"}`,
		"negative size":  `{"size":-1,"hash":"0123456789abcdef"}`,
		"fraction size":  `{"size":1.5,"hash":"0123456789abcdef"}`,
		"huge size":      `{"size":4294967296,"hash":"0123456789abcdef"}`,
		"size as string": `{"size":"10","hash":"0123456789abcdef"}`,
	} {
		_, err := bind(t, "enumerate.web_paths", guessEndpoint(t, "probe", ev))
		if !errors.Is(err, ErrNoEvidence) {
			t.Errorf("%s: err %v, want ErrNoEvidence", name, err)
		}
	}
}

// No other job produces guess: a crawl claiming guess (or anything a crawl
// does not produce) is stored as crawl, and evidence is dropped.
func TestBindSourceNeverGuessOutsideDiscovery(t *testing.T) {
	ev := `{"size":10,"hash":"0123456789abcdef"}`
	cases := []struct {
		capability string
		claim      ctis.EndpointSource
		want       string
	}{
		{"crawl.web@1", "guess", "crawl"},
		{"crawl.web", "dast", "crawl"},
		{"crawl.web", "js", "js"},
		{"crawl.web", "sitemap", "sitemap"},
		{"dast.web", "guess", "crawl"},
		{"dast.web", "dast", "dast"},
		{"", "guess", "crawl"},
		{"", "spec", "spec"},
	}
	for _, c := range cases {
		obs, err := bind(t, c.capability, guessEndpoint(t, c.claim, ev))
		if err != nil {
			t.Fatalf("%s/%s: %v", c.capability, c.claim, err)
		}
		if !slices.Equal(obs.Sources, []string{c.want}) || obs.Evidence != nil {
			t.Errorf("%s claiming %q: sources %v evidence %v, want [%s] and none", c.capability, c.claim, obs.Sources, obs.Evidence, c.want)
		}
	}
}

func TestSourcesIncludeGuess(t *testing.T) {
	if !slices.Contains(Sources(), SourceGuess) {
		t.Fatal("guess is not a filterable source")
	}
}

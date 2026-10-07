package webendpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/weburl"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Observation is one endpoint as one report saw it, normalised by the
// platform: the platform recomputes the origin, the method, the template and
// the parameters from the report's concrete path with ctis/weburl and never
// trusts a producer's template, so a hostile sensor cannot choose the row it
// writes.
type Observation struct {
	Origin       string
	Method       string
	PathTemplate string
	TemplateHash string
	PathHash     string
	ExamplePath  string
	Kind         string
	// Sources are how the endpoint was found (crawl, js, sitemap, ...).
	Sources      []string
	StatusCode   int
	ContentType  string
	AuthState    string
	Technologies []string
	Params       []ParamObservation
	// OutOfScope: the endpoint lies under a scope exclusion. It is stored
	// for visibility and never targeted or alerted on.
	OutOfScope bool
	// ExclusionID names the path exclusion that holds it (OutOfScope).
	ExclusionID *shared.ID
}

// ResponseSig is the hash of what "changed" means for an endpoint: its
// status, content type and auth state. A different signature on a later
// sighting stamps last_changed_at (the incremental selector reads it).
func (o Observation) ResponseSig() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s\n%s", o.StatusCode, o.ContentType, o.AuthState)))
	return hex.EncodeToString(sum[:16])
}

// ParamObservation is one parameter name: never a value.
type ParamObservation struct {
	Location  string
	Name      string
	TypeHint  string
	Required  bool
	RiskHints []string
	Sensitive string
}

// Refusal reasons of an endpoint that is not stored.
var (
	// ErrInvalid: the origin, the path or the method does not parse.
	ErrInvalid = errors.New("invalid endpoint")
	// ErrStatic: a static file (style sheet, image, font, media), counted
	// per origin and never stored.
	ErrStatic = errors.New("static file endpoint")
)

// KindScript is the kind of a JS file endpoint (capped per origin).
const KindScript = string(ctis.EndpointKindScript)

// AuthUnknown is the auth state of an endpoint nothing said about.
const AuthUnknown = string(ctis.EndpointAuthUnknown)

// Observe normalises one CTIS endpoint. The origin must be a normalised web
// origin, the path a concrete absolute path; both are re-parsed, so a query,
// user info or a fragment smuggled into either never reaches storage.
func Observe(e ctis.Endpoint) (Observation, error) {
	o, err := weburl.Parse(e.Origin)
	if err != nil || o.Path != "/" || len(o.Params) > 0 {
		return Observation{}, ErrInvalid
	}
	raw := e.Path
	if raw == "" || raw[0] != '/' || len(raw) > MaxPathBytes || strings.ContainsAny(raw, "?#") {
		return Observation{}, ErrInvalid
	}
	u, err := weburl.Parse(o.Origin() + raw)
	if err != nil || u.Origin() != o.Origin() {
		return Observation{}, ErrInvalid
	}
	method, ok := weburl.NormalizeMethod(e.Method)
	if !ok {
		return Observation{}, ErrInvalid
	}
	kind := kindOf(e.Kind)
	if kind == string(ctis.EndpointKindStatic) {
		return Observation{}, ErrStatic
	}
	tmpl := u.Template()
	if len(tmpl) > MaxPathBytes {
		return Observation{}, ErrInvalid
	}
	obs := Observation{
		Origin:       u.Origin(),
		Method:       method,
		PathTemplate: tmpl,
		TemplateHash: weburl.PathHash(method, tmpl),
		PathHash:     PatternHash(tmpl),
		ExamplePath:  MaskPath(u.Path),
		Kind:         kind,
		Sources:      []string{sourceOf(e.Source)},
		AuthState:    authOf(e.Auth),
		ContentType:  contentType(e.ContentType),
		Technologies: technologyNames(e.Technologies),
	}
	if e.StatusCode >= 100 && e.StatusCode <= 599 {
		obs.StatusCode = e.StatusCode
	}
	obs.Params = observeParams(e.Params, u.Params)
	return obs, nil
}

// PatternHash is the host-less, method-less key of a path template: the
// path-pattern view groups the endpoints of every origin of one tenant by
// it ("where does /actuator/env exist?"). It is never compared across
// tenants.
func PatternHash(template string) string {
	sum := sha256.Sum256([]byte(template))
	return hex.EncodeToString(sum[:])
}

// MaskPath is a concrete path safe to keep as the one example of an
// endpoint: every segment the templating treats as a token, a hex digest,
// an e-mail address or an opaque identifier is replaced by its variable, so
// a reset token or a signed path never lands in the database. Integers,
// UUIDs and dates stay concrete: they help a person reproduce the request.
func MaskPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		switch t := weburl.TemplateSegment(s); t {
		case "{int}", "{uuid}", "{date}", s:
		default:
			segs[i] = t
		}
	}
	return strings.Join(segs, "/")
}

func kindOf(k ctis.EndpointKind) string {
	for _, v := range ctis.AllEndpointKinds() {
		if k == v {
			return string(k)
		}
	}
	return string(ctis.EndpointKindPage)
}

func sourceOf(s ctis.EndpointSource) string {
	for _, v := range ctis.AllEndpointSources() {
		if s == v {
			return string(s)
		}
	}
	return string(ctis.EndpointSourceCrawl)
}

func authOf(a ctis.EndpointAuth) string {
	for _, v := range ctis.AllEndpointAuths() {
		if a == v {
			return string(a)
		}
	}
	return AuthUnknown
}

// contentType keeps the media type only (no parameters such as a charset
// or a boundary), lower-cased and bounded.
func contentType(ct string) string {
	ct, _, _ = strings.Cut(ct, ";")
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" || len(ct) > MaxContentTypeBytes || strings.IndexFunc(ct, unicode.IsControl) >= 0 {
		return ""
	}
	return ct
}

func technologyNames(ts []ctis.Technology) []string {
	out := make([]string, 0, min(len(ts), MaxTechnologies))
	for _, t := range ts {
		n := strings.TrimSpace(t.Name)
		if n == "" || len(n) > 64 || strings.IndexFunc(n, unicode.IsControl) >= 0 || slices.Contains(out, n) {
			continue
		}
		out = append(out, n)
		if len(out) == MaxTechnologies {
			break
		}
	}
	return out
}

func validLocation(l ctis.ParamLocation) bool {
	return slices.Contains(ctis.AllParamLocations(), l)
}

// observeParams merges the endpoint's declared parameters with the query
// parameter names of its path, bounded and de-duplicated. A name with a
// control character, or longer than MaxParamNameBytes, is dropped.
func observeParams(declared []ctis.EndpointParam, queryNames []string) []ParamObservation {
	out := make([]ParamObservation, 0, min(len(declared)+len(queryNames), MaxParamsPerEndpoint))
	seen := map[string]bool{}
	add := func(loc, name, hint string, required bool) {
		name = strings.TrimSpace(name)
		if name == "" || len(name) > MaxParamNameBytes || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return
		}
		key := loc + "\x00" + name
		if seen[key] || len(out) >= MaxParamsPerEndpoint {
			return
		}
		seen[key] = true
		risk, sensitive := ClassifyParam(name)
		out = append(out, ParamObservation{
			Location: loc, Name: name, TypeHint: typeHint(hint), Required: required,
			RiskHints: risk, Sensitive: sensitive,
		})
	}
	for _, p := range declared {
		if validLocation(p.Location) {
			add(string(p.Location), p.Name, p.TypeHint, p.Required)
		}
	}
	for _, n := range queryNames {
		add(string(ctis.ParamLocationQuery), n, "", false)
	}
	return out
}

func typeHint(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || len(h) > 16 {
		return ""
	}
	for _, r := range h {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return ""
		}
	}
	return h
}

package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/app/contentrule/builtin"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/templatefact"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func builtinFacts(t *testing.T) *templatefact.Map {
	t.Helper()
	m, err := builtin.TemplateFacts()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The real nuclei run (2 tech-detect, 10 missing-header matches, a medium
// and a high): the technologies join the report asset, the header matches
// become the origin's posture, nothing becomes an exposure, and the
// vulnerabilities stay findings.
func TestInfoFactsRealNucleiRun(t *testing.T) {
	report, assetMap, _ := infoReport(t)
	facts := builtinFacts(t)
	scope := fullScope()

	enriched := applyInfoFacts(report, facts, scope)
	if enriched == report {
		t.Fatal("report not copied")
	}
	var origin *ctis.Asset
	for i := range enriched.Assets {
		if enriched.Assets[i].Type == ctis.AssetTypeWebOrigin {
			origin = &enriched.Assets[i]
		}
	}
	if origin == nil {
		t.Fatal("fixture has no web origin")
	}
	names := map[string]bool{}
	for _, tech := range origin.Technologies {
		names[tech.Name] = true
		if tech.Confidence <= 0 || tech.Confidence >= 80 {
			t.Errorf("%s confidence %d: a template detection is never strong", tech.Name, tech.Confidence)
		}
	}
	if !names["python"] || !names["simplehttp"] || len(names) != 2 {
		t.Fatalf("technologies %v", names)
	}
	for i := range report.Assets {
		if len(report.Assets[i].Technologies) != 0 {
			t.Fatal("the caller's report was changed")
		}
	}

	// Posture: what the report's headers do not decide comes from the
	// missing-header matches.
	sanitizeHTTPPosture(enriched, scope)
	p, _ := origin.Properties[webendpoint.PostureKey].(map[string]any)
	for k, want := range map[string]any{"hsts": false, "csp": false, "nosniff": false, "permissions_policy": false, "frame_options": "none", "referrer_policy": "none"} {
		if p[k] != want {
			t.Errorf("posture %s = %v, want %v (%v)", k, p[k], want, p)
		}
	}

	proj, rec := &fakeTemplateMatches{}, &fakeStepInfo{}
	s := &Service{logger: logger.NewNop(), templateMatches: proj, stepInfo: rec}
	step := shared.NewID()
	out := &Output{}
	s.routeInfoMatches(context.Background(), shared.NewID(), enriched, assetMap, out, Binding{Kind: BindingCommand, StepRunID: &step}, facts)
	if len(enriched.Findings) != 2 {
		t.Fatalf("findings left %d, want the medium and the high", len(enriched.Findings))
	}
	if len(proj.got) != 0 || out.InfoFacts != 12 || out.InfoObservations != 12 || out.InfoUnmapped != 0 || rec.n != 12 {
		t.Fatalf("exposures %d facts %d observations %d unmapped %d step %d", len(proj.got), out.InfoFacts, out.InfoObservations, out.InfoUnmapped, rec.n)
	}
}

func factReport(findings ...ctis.Finding) *ctis.Report {
	return &ctis.Report{
		Tool:     &ctis.Tool{Name: "nuclei"},
		Assets:   []ctis.Asset{{ID: "o1", Type: ctis.AssetTypeWebOrigin, Value: "https://a.example"}},
		Findings: findings,
	}
}

func infoMatch(rule, matcher, url string, extracted ...string) ctis.Finding {
	f := ctis.Finding{RuleID: rule, Severity: ctis.SeverityInfo, AssetRef: "o1", Web: &ctis.WebLocation{URL: url},
		SourceExtra: map[string]string{"matcher_name": matcher}}
	if len(extracted) > 0 {
		f.EvidenceItems = []ctis.EvidenceItem{{Kind: "http_exchange", Extracted: extracted}}
	}
	return f
}

func TestInfoFactsSurfaceAndVersions(t *testing.T) {
	facts := builtinFacts(t)
	r := applyInfoFacts(factReport(
		infoMatch("robots-txt-endpoint", "", "https://a.example/robots.txt", "/admin", "https://b.example/x", "/wp-*"),
		infoMatch("security-txt", "", "https://a.example/.well-known/security.txt"),
		infoMatch("nginx-version", "", "https://a.example/", "nginx/1.25.3"),
		infoMatch("tech-detect", "nginx", "https://a.example/"),
		infoMatch("email-extractor", "", "https://a.example/", "someone@example.com"),
	), facts, fullScope())
	paths := map[string]string{}
	for _, e := range r.Endpoints {
		if e.Origin != "https://a.example" || e.OriginRef != "o1" {
			t.Fatalf("endpoint %+v", e)
		}
		paths[e.Path] = string(e.Source)
	}
	if len(paths) != 2 || paths["/admin"] != "robots" || paths["/.well-known/security.txt"] != "probe" {
		t.Fatalf("endpoints %v", paths)
	}
	techs := r.Assets[0].Technologies
	if len(techs) != 1 || techs[0].Name != "nginx" || techs[0].Version != "1.25.3" {
		t.Fatalf("one nginx with the extracted version, got %+v", techs)
	}
}

// A sensitive extracted value is never read; a tool's own typed technology
// is not duplicated; a report that is not a template scanner's is untouched.
func TestInfoFactsBoundaries(t *testing.T) {
	facts := builtinFacts(t)
	f := infoMatch("nginx-version", "", "https://a.example/", "nginx/9.9.9")
	f.EvidenceItems[0].Sensitive = []ctis.SensitiveSpan{{Pointer: "/extracted/0"}}
	rep := factReport(f)
	rep.Assets[0].Technologies = []ctis.Technology{{Name: "NGINX", Version: "1.25.3"}}
	r := applyInfoFacts(rep, facts, fullScope())
	if len(r.Assets[0].Technologies) != 1 || r.Assets[0].Technologies[0].Version != "1.25.3" {
		t.Fatalf("got %+v", r.Assets[0].Technologies)
	}

	other := factReport(infoMatch("tech-detect", "nginx", "https://a.example/"))
	other.Tool.Name = "httpx"
	if got := applyInfoFacts(other, facts, fullScope()); got != other {
		t.Fatal("a non-template report was rewritten")
	}

	// A match on an asset ref the report does not hold adds nothing.
	stray := factReport(infoMatch("tech-detect", "nginx", "https://a.example/"))
	stray.Findings[0].AssetRef = "missing"
	if got := applyInfoFacts(stray, facts, fullScope()); len(got.Assets[0].Technologies) != 0 {
		t.Fatal("a match without its asset added a technology")
	}

	// Posture keys from a template never override the report's own header
	// reading, and only web origins get them.
	hdr := factReport(infoMatch("http-missing-security-headers", "strict-transport-security", "https://a.example/"))
	hdr.Assets[0].Technical = &ctis.AssetTechnical{HTTP: &ctis.HTTPTechnical{SecurityHeaders: &ctis.SecurityHeaders{StrictTransportSecurity: "max-age=10"}}}
	sc := fullScope()
	hr := applyInfoFacts(hdr, facts, sc)
	sanitizeHTTPPosture(hr, sc)
	if p := hr.Assets[0].Properties[webendpoint.PostureKey].(map[string]any); p["hsts"] != true {
		t.Fatalf("template overrode the report's headers: %v", p)
	}
	svc := factReport(infoMatch("http-missing-security-headers", "strict-transport-security", "https://a.example/"))
	svc.Assets[0].Type = ctis.AssetTypeService
	sc2 := fullScope()
	sanitizeHTTPPosture(applyInfoFacts(svc, facts, sc2), sc2)
	if len(sc2.templatePosture) != 0 {
		t.Fatal("posture recorded for a non-origin asset")
	}
}

// Unmapped info matches stay generic exposures and are counted; panels
// stay exposures with their type.
func TestInfoMatchesUnmappedAndPanels(t *testing.T) {
	facts := builtinFacts(t)
	panel := infoMatch("grafana-login", "", "https://a.example/login")
	panel.Tags = []string{"panel", "grafana"}
	rep := factReport(infoMatch("brand-new-template", "", "https://a.example/"), panel)
	proj := &fakeTemplateMatches{}
	s := &Service{logger: logger.NewNop(), templateMatches: proj}
	out := &Output{}
	s.routeInfoMatches(context.Background(), shared.NewID(), rep, map[string]shared.ID{"o1": shared.NewID()}, out, Binding{}, facts)
	if len(proj.got) != 2 || out.InfoUnmapped != 1 || out.InfoFacts != 0 || len(rep.Findings) != 0 {
		t.Fatalf("exposures %d unmapped %d facts %d left %d", len(proj.got), out.InfoUnmapped, out.InfoFacts, len(rep.Findings))
	}
	if proj.got[1].EventType != "web_interface_exposed" {
		t.Fatalf("panel type %q", proj.got[1].EventType)
	}
}

func TestSecondaryTechnologiesAreMarked(t *testing.T) {
	rep := factReport()
	rep.Assets[0].Technologies = []ctis.Technology{{Name: "nginx"}}
	id := shared.NewID()
	repo := &captureTechs{}
	s := &Service{logger: logger.NewNop(), techs: repo}
	s.recordTechnologies(context.Background(), shared.NewID(), fullScope(), attributeSource{name: "nuclei"}, time.Now(), rep, map[string]shared.ID{"o1": id})
	if len(repo.got) != 1 || !repo.got[0].Secondary {
		t.Fatalf("template scanner technology not secondary: %+v", repo.got)
	}
	rep.Tool.Name = "httpx"
	repo.got = nil
	s.recordTechnologies(context.Background(), shared.NewID(), fullScope(), attributeSource{name: "httpx"}, time.Now(), rep, map[string]shared.ID{"o1": id})
	if len(repo.got) != 1 || repo.got[0].Secondary {
		t.Fatalf("probe technology marked secondary: %+v", repo.got)
	}
}

type captureTechs struct {
	assettech.Repository
	got []assettech.Technology
}

func (c *captureTechs) Enrich(_ context.Context, _ shared.ID, techs []assettech.Technology) error {
	c.got = append(c.got, techs...)
	return nil
}

type fakeRules struct{ e *contentrule.Engine }

func (f fakeRules) Engine(context.Context, shared.ID) (*contentrule.Engine, error) { return f.e, nil }
func (fakeRules) Fingerprinter(shared.ID) contentrule.Fingerprinter {
	return func(v string) string { return v }
}
func (fakeRules) RecordAssetSecrets(context.Context, shared.ID, shared.ID, string, []contentrule.SecretMatch) error {
	return nil
}
func (fakeRules) RecordPins(context.Context, shared.ID, shared.ID, *contentrule.Engine) {}

// A technology both a detection rule and a template match state keeps the
// rule's source: the rules run before the facts are added.
func TestDetectionRuleKeepsItsSourceOverTemplateFact(t *testing.T) {
	e, errs := contentrule.Compile([]contentrule.RuleSet{{
		Kind:   contentrule.KindFingerprint,
		Origin: contentrule.Origin{Scope: contentrule.ScopePlatform, Pack: "web-fingerprints-core", Version: "1"},
		Rules: []contentrule.Rule{{ID: "nginx", Name: "nginx", Confidence: 90,
			Technology: &contentrule.Technology{Name: "nginx", Category: "web_server"},
			Matchers:   []contentrule.Matcher{{Location: contentrule.LocHeader, Header: "server", Keywords: []string{"nginx"}, Pattern: `(?i)^nginx`}}}},
	}})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	rep := factReport(infoMatch("tech-detect", "nginx", "https://a.example/"))
	rep.Assets[0].Technical = &ctis.AssetTechnical{HTTP: &ctis.HTTPTechnical{WebServer: "nginx/1.25.3"}}
	s := &Service{logger: logger.NewNop(), rules: fakeRules{e}}
	out, plan := s.detectThenApplyFacts(context.Background(), shared.NewID(), rep, builtinFacts(t), fullScope())
	if plan == nil || len(plan.techs["o1"]) != 1 || plan.techs["o1"][0].Origin.Source() != "rules:web-fingerprints-core@1" {
		t.Fatalf("the detection rule's technology was not kept for recording: %+v", plan)
	}
	n := 0
	for _, tech := range out.Assets[0].Technologies {
		if assettech.Key(tech.Name) == "nginx" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("nginx stated %d times", n)
	}
}

// A template match fills only the posture keys the stored http_posture
// lacks; a probe's stored value wins across reports.
func TestTemplatePostureKeepsStoredValues(t *testing.T) {
	stored := map[string]any{webendpoint.PostureKey: map[string]any{"hsts": true, "nosniff": true}}
	merged := map[string]any{webendpoint.PostureKey: map[string]any{"hsts": false, "frame_options": "none", "nosniff": true}}
	keepStoredPosture(stored, merged)
	got := merged[webendpoint.PostureKey].(map[string]any)
	if got["hsts"] != true || got["frame_options"] != "none" || got["nosniff"] != true {
		t.Fatalf("posture %v", got)
	}

	// Through the merge of an existing asset: a template report (nuclei)
	// does not override, a probe's (httpx) does.
	p := NewAssetProcessor(nil, logger.NewNop())
	mk := func() *asset.Asset {
		a, err := asset.NewAssetWithTenant(shared.NewID(), "https://a.example", asset.AssetTypeService, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		a.SetProperties(map[string]any{webendpoint.PostureKey: map[string]any{"hsts": true}})
		return a
	}
	rep := ctis.Asset{ID: "o1", Type: ctis.AssetTypeWebOrigin, Value: "https://a.example",
		Properties: ctis.Properties{webendpoint.PostureKey: map[string]any{"hsts": false, "frame_options": "none"}}}
	a := mk()
	p.mergeCTISIntoAsset(a, &rep, &ctis.Tool{Name: "nuclei"}, time.Time{}, nil)
	pos, _ := a.Properties()[webendpoint.PostureKey].(map[string]any)
	if pos["hsts"] != true || pos["frame_options"] != "none" {
		t.Fatalf("template report overrode the stored posture: %v", a.Properties())
	}
	a = mk()
	p.mergeCTISIntoAsset(a, &rep, &ctis.Tool{Name: "httpx"}, time.Time{}, nil)
	pos, _ = a.Properties()[webendpoint.PostureKey].(map[string]any)
	if pos["hsts"] != false {
		t.Fatalf("a probe report no longer updates the posture: %v", a.Properties())
	}
}

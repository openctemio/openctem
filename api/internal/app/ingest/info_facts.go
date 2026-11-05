package ingest

// Template facts (docs/architecture/template-facts.md): an info match of a
// template scanner is a fact about its asset, not a vulnerability. Before
// anything is stored, the matches the mapping names enrich the report asset
// they are about, so the ordinary pipelines store them with that asset's
// admission (scope, exclusions, the bound job):
//
//   - technology: a typed technology of the report asset. Set
//     reconciliation records it as a sighting of the template scanner (it
//     never removes what it did not report, and it leaves after the scan
//     TTL when no scan sees it again), asset_technologies keeps a
//     fingerprinting probe's source over it, and a versioned one becomes a
//     banner-class reading of the technology history (never strong alone).
//   - posture: http_posture keys of the web origin (header posture is an
//     attribute, never one finding per header).
//   - surface: web surface entries of the origin (source probe, robots or
//     sitemap), through the endpoint plan's target and scope checks.
//   - discard: nothing is stored.
//
// routeInfoMatches then takes these matches out of the findings (counted
// as info observations); exposure-class matches and the ones the mapping
// does not name become info exposures as before.

import (
	"context"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/weburl"

	"github.com/openctemio/openctem/api/internal/app/contentrule/builtin"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/templatefact"
)

// TemplateFactsSource gives the template facts mapping
// (*contentrule.Service: the stable platform pack, else the embedded one).
type TemplateFactsSource interface {
	TemplateFacts(ctx context.Context) *templatefact.Map
}

// SetTemplateFacts wires the mapping. Nil-safe: unwired, the embedded
// mapping is used.
func (s *Service) SetTemplateFacts(src TemplateFactsSource) { s.templateFacts = src }

// templateFactsMap is the mapping this ingest routes with (nil when the
// embedded one is invalid, which a test forbids).
func (s *Service) templateFactsMap(ctx context.Context) *templatefact.Map {
	if s.templateFacts != nil {
		if m := s.templateFacts.TemplateFacts(ctx); m != nil {
			return m
		}
	}
	m, _ := builtin.TemplateFacts()
	return m
}

// maxFactEndpointsPerReport bounds the surface entries the mapping adds to
// one report.
const maxFactEndpointsPerReport = 2000

// factInput reads one finding as a mapping input. Extracted values marked
// sensitive are left out.
func factInput(f *ctis.Finding) templatefact.Input {
	in := templatefact.Input{TemplateID: f.RuleID, Tags: f.Tags, Matcher: f.SourceExtra["matcher_name"]}
	if f.Web != nil {
		in.URL = f.Web.URL
	}
	if f.Vulnerability != nil {
		in.CPE = f.Vulnerability.CPE
	}
	in.Metadata = templateMetadata(f.SourceExtra["template_metadata"])
	for i := range f.EvidenceItems {
		it := &f.EvidenceItems[i]
		for k, v := range it.Extracted {
			if len(in.Extracted) == templatefact.MaxPaths {
				return in
			}
			if !extractedSensitive(it, k) {
				in.Extracted = append(in.Extracted, v)
			}
		}
	}
	return in
}

func extractedSensitive(it *ctis.EvidenceItem, k int) bool {
	ptr := "/extracted/" + strconv.Itoa(k)
	for _, s := range it.Sensitive {
		if s.Pointer == ptr {
			return true
		}
	}
	return false
}

// templateMetadata parses the importer's "key=value" lines (values are the
// template's JSON scalars; strings are unquoted). At most 32 keys.
func templateMetadata(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		if len(out) == 32 {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if u, err := strconv.Unquote(strings.TrimSpace(v)); err == nil {
			v = u
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// factInfoMatch reports whether f is a template scanner's info match the
// mapping routes (report tool checked by the caller).
func factInfoMatch(f *ctis.Finding) bool {
	return f.Severity == ctis.SeverityInfo && f.AssetRef != ""
}

// applyInfoFacts returns the report with the facts of its template info
// matches added to the report assets and endpoints (a copy: the caller's
// report is not changed), and stores the posture each web origin's matches
// prove in scope (sanitizeHTTPPosture applies it). Matches stay in the
// findings; routeInfoMatches takes them out.
func applyInfoFacts(report *ctis.Report, m *templatefact.Map, scope *alterScope) *ctis.Report {
	if report == nil || m == nil || report.Tool == nil || !templateScanner(report.Tool.Name) || len(report.Findings) == 0 {
		return report
	}
	byRef := make(map[string]int, len(report.Assets))
	for i := range report.Assets {
		if report.Assets[i].ID != "" {
			byRef[report.Assets[i].ID] = i
		}
	}
	r := *report
	r.Assets = append([]ctis.Asset(nil), report.Assets...)
	r.Endpoints = append([]ctis.Endpoint(nil), report.Endpoints...)
	copied := map[int]bool{}
	added := 0
	for i := range report.Findings {
		f := &report.Findings[i]
		if !factInfoMatch(f) {
			continue
		}
		ai, ok := byRef[f.AssetRef]
		if !ok {
			continue
		}
		fact, ok := m.Classify(factInput(f))
		if !ok {
			continue
		}
		a := &r.Assets[ai]
		switch fact.Class {
		case templatefact.ClassTechnology:
			if !copied[ai] {
				a.Technologies = append([]ctis.Technology(nil), a.Technologies...)
				copied[ai] = true
			}
			for _, t := range fact.Technologies {
				addFactTechnology(a, t)
			}
		case templatefact.ClassPosture:
			if a.Type == ctis.AssetTypeWebOrigin && len(fact.Posture) > 0 {
				scope.addTemplatePosture(a.ID, fact.Posture)
			}
		case templatefact.ClassSurface:
			origin := factOrigin(f)
			for _, p := range fact.Paths {
				if origin == "" || added == maxFactEndpointsPerReport {
					break
				}
				e := ctis.Endpoint{Origin: origin, Method: "GET", Path: p, Kind: ctis.EndpointKindOther, Source: ctis.EndpointSource(fact.Source)}
				if a.Type == ctis.AssetTypeWebOrigin {
					e.OriginRef = a.ID
				}
				r.Endpoints = append(r.Endpoints, e)
				added++
			}
		}
	}
	return &r
}

// addFactTechnology adds t to the asset's technologies unless the report
// already states that technology (the tool's own typed report wins), at
// most assettech.MaxPerAsset.
func addFactTechnology(a *ctis.Asset, t templatefact.Technology) {
	key := assettech.Key(t.Name)
	if key == "" || len(a.Technologies) >= assettech.MaxPerAsset {
		return
	}
	for i := range a.Technologies {
		if assettech.Key(a.Technologies[i].Name) != key {
			continue
		}
		// The same product from another match: keep a version one of them
		// read.
		if a.Technologies[i].Version == "" && t.Version != "" {
			a.Technologies[i].Version = t.Version
		}
		return
	}
	ct := ctis.Technology{Name: t.Name, Version: t.Version, CPE: t.CPE, Confidence: t.Confidence}
	if t.Category != "" {
		ct.Categories = []string{t.Category}
	}
	a.Technologies = append(a.Technologies, ct)
}

// factOrigin is the normalised origin of the match's URL ("" when none).
func factOrigin(f *ctis.Finding) string {
	if f.Web == nil {
		return ""
	}
	u, err := weburl.Parse(f.Web.URL)
	if err != nil {
		return ""
	}
	return u.Origin()
}

// infoFactClass is the class the mapping gives a report finding, ok false
// when it names none.
func infoFactClass(m *templatefact.Map, f *ctis.Finding) (templatefact.Fact, bool) {
	if m == nil || !factInfoMatch(f) {
		return templatefact.Fact{}, false
	}
	return m.Classify(factInput(f))
}

// addTemplatePosture merges posture keys proven by a template match into
// the report asset's template posture. Nil-safe.
func (s *alterScope) addTemplatePosture(ref string, keys map[string]any) {
	if s == nil || ref == "" {
		return
	}
	if s.templatePosture == nil {
		s.templatePosture = map[string]map[string]any{}
	}
	p := s.templatePosture[ref]
	if p == nil {
		p = map[string]any{}
		s.templatePosture[ref] = p
	}
	for k, v := range keys {
		p[k] = v
	}
}

// templatePostureFor is the template posture of a report asset (nil-safe).
func (s *alterScope) templatePostureFor(ref string) map[string]any {
	if s == nil {
		return nil
	}
	return s.templatePosture[ref]
}

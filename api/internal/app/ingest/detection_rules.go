package ingest

// Detection rules at ingest (docs/rfcs/RFC-140-rule-packs.md): each web
// service a report states is turned into a document (URL, title, Server
// header, cookie names, favicon hash, the script paths the report found on
// it) and scanned with the organization's engine before anything is
// stored. Fingerprint matches join the asset's technologies (and through
// them software components); secret matches become exposures on the assets
// this report may change, masked. Best effort: a failure is logged and
// never fails the report.

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// DetectionRules gives each organization its detection rule engine and
// records what it finds.
type DetectionRules interface {
	Engine(ctx context.Context, tenantID shared.ID) (*contentrule.Engine, error)
	Fingerprinter(tenantID shared.ID) contentrule.Fingerprinter
	RecordAssetSecrets(ctx context.Context, tenantID, assetID shared.ID, url string, secrets []contentrule.SecretMatch) error
	RecordPins(ctx context.Context, tenantID, commandID shared.ID, e *contentrule.Engine)
}

// SetDetectionRules wires detection rules (nil = not run).
func (s *Service) SetDetectionRules(r DetectionRules) { s.rules = r }

// maxRuleDocsPerReport bounds the documents one report is scanned for.
const maxRuleDocsPerReport = 500

// detectionPlan is what the rules found in a report, by report asset id,
// until the assets are stored.
type detectionPlan struct {
	engine  *contentrule.Engine
	secrets map[string]docSecrets
	techs   map[string][]contentrule.TechMatch
}

type docSecrets struct {
	url     string
	secrets []contentrule.SecretMatch
}

// matchDetectionRules scans the report's web services and returns the
// report with the detected technologies added to its assets (a copy when
// anything is added), and what is left to record once the assets exist.
func (s *Service) matchDetectionRules(ctx context.Context, tenantID shared.ID, report *ctis.Report) (*ctis.Report, *detectionPlan) {
	if s.rules == nil || report == nil {
		return report, nil
	}
	e, err := s.rules.Engine(ctx, tenantID)
	if err != nil {
		s.logger.Warn("detection rules not run", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return report, nil
	}
	if e == nil {
		return report, nil
	}
	plan := &detectionPlan{engine: e, secrets: map[string]docSecrets{}, techs: map[string][]contentrule.TechMatch{}}
	fp := s.rules.Fingerprinter(tenantID)
	var out *ctis.Report
	docs, stopped := 0, 0
	for i := range report.Assets {
		a := &report.Assets[i]
		if a.Type != ctis.AssetTypeHTTPService || a.ID == "" {
			continue
		}
		if docs >= maxRuleDocsPerReport {
			break
		}
		docs++
		doc := webDocument(a, report.Endpoints)
		res := e.Scan(ctx, doc, contentrule.DefaultBudget, fp)
		if res.Stopped != "" {
			stopped++
		}
		if len(res.Secrets) > 0 {
			plan.secrets[a.ID] = docSecrets{url: doc.URL, secrets: res.Secrets}
		}
		added := newTechnologies(a, res.Technologies)
		if len(added) == 0 {
			continue
		}
		plan.techs[a.ID] = added
		if out == nil {
			r := *report
			r.Assets = append([]ctis.Asset(nil), report.Assets...)
			out = &r
		}
		techs := append([]ctis.Technology(nil), a.Technologies...)
		for _, t := range added {
			techs = append(techs, ctis.Technology{Name: t.Name, Version: t.Version, CPE: t.CPE, Confidence: t.Confidence, Categories: categories(t.Category)})
		}
		out.Assets[i].Technologies = techs
	}
	if stopped > 0 {
		s.logger.Info("detection rule scans stopped by their budget", "tenant_id", tenantID.String(), "documents", stopped)
	}
	if out == nil {
		out = report
	}
	return out, plan
}

// recordDetectionRules records, once the assets are stored, the secrets on
// the assets this report may change, the source of the detected
// technologies, and on a command the rule sets the report was matched with.
func (s *Service) recordDetectionRules(ctx context.Context, tenantID shared.ID, scope *alterScope, binding Binding,
	plan *detectionPlan, assetMap map[string]shared.ID, observedAt time.Time,
) {
	if plan == nil || s.rules == nil {
		return
	}
	for ref, ds := range plan.secrets {
		id, ok := assetMap[ref]
		if !ok || id.IsZero() || !scope.allowedAsset(id) {
			continue
		}
		if err := s.rules.RecordAssetSecrets(ctx, tenantID, id, ds.url, ds.secrets); err != nil {
			s.logger.Warn("detection rule exposures not recorded", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
	if s.techs != nil && len(plan.techs) > 0 {
		if observedAt.IsZero() || observedAt.After(time.Now()) {
			observedAt = time.Now()
		}
		var techs []assettech.Technology
		for ref, ms := range plan.techs {
			id, ok := assetMap[ref]
			if !ok || id.IsZero() || !scope.allowedAsset(id) {
				continue
			}
			for _, m := range ms {
				t, ok := assettech.Observation(id, m.Name, m.Version, categories(m.Category), m.Confidence, m.Origin.Source(), observedAt)
				if ok {
					techs = append(techs, t.WithCPE(m.CPE))
				}
			}
		}
		if len(techs) > 0 {
			if err := s.techs.Enrich(ctx, tenantID, techs); err != nil {
				s.logger.Warn("detection rule technologies not enriched", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
			}
		}
	}
	if binding.CommandID != nil {
		s.rules.RecordPins(ctx, tenantID, *binding.CommandID, plan.engine)
	}
}

// newTechnologies are the detections the asset does not already state: a
// tool's own report of a technology wins over a rule's.
func newTechnologies(a *ctis.Asset, ms []contentrule.TechMatch) []contentrule.TechMatch {
	if len(ms) == 0 {
		return nil
	}
	have := map[string]bool{}
	for _, t := range a.Technologies {
		have[assettech.Key(t.Name)] = true
	}
	for _, key := range []string{"technologies", "technology"} {
		for _, el := range stringList(a.Properties[key]) {
			name, _ := assettech.Split(el)
			have[assettech.Key(name)] = true
		}
	}
	out := make([]contentrule.TechMatch, 0, len(ms))
	for _, m := range ms {
		k := assettech.Key(m.Name)
		if k == "" || have[k] {
			continue
		}
		have[k] = true
		out = append(out, m)
	}
	return out
}

func categories(c string) []string {
	if c == "" {
		return nil
	}
	return []string{c}
}

// webDocument is what the platform knows of a web service from its report:
// the URL, the final URL, the title, the Server header, the cookie names
// of its header posture, the favicon hash and the script paths the report
// found under its origin. No value of a cookie or other header is ever
// present in a report.
func webDocument(a *ctis.Asset, endpoints []ctis.Endpoint) contentrule.Document {
	doc := contentrule.Document{
		URL:      a.Value,
		FinalURL: stringProperty(a.Properties, []string{"redirect_url", "final_url"}),
		Title:    stringProperty(a.Properties, []string{"title"}),
		Favicon:  stringProperty(a.Properties, []string{"favicon_mmh3"}),
	}
	if doc.URL == "" {
		doc.URL = stringProperty(a.Properties, []string{"url"})
	}
	if srv := stringProperty(a.Properties, []string{"web_server", "server"}); srv != "" {
		doc.Headers = map[string]string{"server": srv}
	}
	if posture, ok := a.Properties[ctis.HTTPPostureProperty].(map[string]any); ok {
		if cookies, ok := posture["cookies"].([]any); ok {
			for _, c := range cookies {
				if m, ok := c.(map[string]any); ok {
					if n, ok := m["name"].(string); ok && n != "" {
						doc.Cookies = append(doc.Cookies, n)
					}
				}
			}
		}
	}
	origin := originOf(doc.URL)
	for i := range endpoints {
		ep := &endpoints[i]
		if ep.OriginRef != a.ID && (origin == "" || originOf(ep.Origin) != origin) {
			continue
		}
		if ep.Kind == ctis.EndpointKindScript || strings.HasSuffix(strings.ToLower(ep.Path), ".js") {
			doc.Scripts = append(doc.Scripts, ep.Path)
		}
		if len(doc.Scripts) >= contentrule.MaxScripts {
			break
		}
	}
	return doc
}

// originOf is scheme://host[:port] in lower case, without a default port;
// "" when raw is not an absolute http(s) URL.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	const schemeHTTP, schemeHTTPS = "http", "https"
	if err != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == schemeHTTP && port == "80") || (u.Scheme == schemeHTTPS && port == "443") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

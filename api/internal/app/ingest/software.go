package ingest

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Software inventory capture (RFC-066 §6): the products a report says its
// assets run are resolved against the software catalog and linked to the
// assets in asset_software. Best-effort: a failure is logged and never
// fails the report.

// Caps on what one report may add to the inventory.
const (
	maxSoftwarePerAsset  = 200
	maxSoftwarePerReport = 5000
)

// SoftwareChangeSink receives the assets whose software changed, for the
// vulnerability matcher.
type SoftwareChangeSink interface {
	SoftwareChanged(tenantID shared.ID, assetIDs []shared.ID)
}

type softwareRecorder struct {
	repo software.Repository
	sink SoftwareChangeSink

	mu        sync.Mutex
	ready     bool
	lastTried time.Time
}

// curatedRetry is how long a failed write of the curated products waits
// before the next report tries again.
const curatedRetry = 10 * time.Minute

// errCuratedPending: the curated products have not been written yet.
var errCuratedPending = errors.New("curated products not written yet")

// ensureCurated writes the curated products once per process. Until it has
// succeeded, names would resolve to tenant-private products only, so the
// inventory waits for it.
func (r *softwareRecorder) ensureCurated(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ready {
		return nil
	}
	if !r.lastTried.IsZero() && time.Since(r.lastTried) < curatedRetry {
		return errCuratedPending
	}
	r.lastTried = time.Now()
	if err := r.repo.EnsureCurated(ctx, software.CuratedProducts()); err != nil {
		return err
	}
	r.ready = true
	return nil
}

type softwareWork struct {
	assetID shared.ID
	obs     []software.Observation
}

// SetSoftwareRepository wires the software inventory. Unwired, reports keep
// working and no inventory is captured.
func (s *Service) SetSoftwareRepository(repo software.Repository) {
	s.software = &softwareRecorder{repo: repo}
}

// SetSoftwareChangeSink wires the matcher's queue of changed assets.
func (s *Service) SetSoftwareChangeSink(sink SoftwareChangeSink) {
	if s.software != nil {
		s.software.sink = sink
	}
}

// recordSoftware captures the software observations of the report's assets
// that this report was allowed to write.
func (s *Service) recordSoftware(ctx context.Context, tenantID shared.ID, scope *alterScope,
	report *ctis.Report, assetMap map[string]shared.ID,
) {
	if s.software == nil || report == nil || len(assetMap) == 0 {
		return
	}
	rec := s.software
	if err := rec.ensureCurated(ctx); err != nil {
		s.logger.Warn("software inventory skipped: curated products not written", "error", logger.SanitizeError(err))
		return
	}
	var work []softwareWork
	total := 0
	for i := range report.Assets {
		a := &report.Assets[i]
		id, ok := assetMap[a.ID]
		if !ok || id.IsZero() || !scope.allowedAsset(id) {
			continue
		}
		obs := softwareObservations(a)
		if len(obs) > maxSoftwarePerAsset {
			obs = obs[:maxSoftwarePerAsset]
		}
		if total+len(obs) > maxSoftwarePerReport {
			obs = obs[:maxSoftwarePerReport-total]
		}
		total += len(obs)
		if len(obs) > 0 {
			work = append(work, softwareWork{assetID: id, obs: obs})
		}
		if total >= maxSoftwarePerReport {
			break
		}
	}
	if len(work) == 0 {
		return
	}
	links, err := s.resolveSoftware(ctx, tenantID, work)
	if err != nil {
		s.logger.Warn("software inventory not recorded", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	res, err := rec.repo.UpsertLinks(ctx, tenantID, links)
	if err != nil {
		s.logger.Warn("software inventory not recorded", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	if rec.sink != nil && len(res.ChangedAssets) > 0 {
		rec.sink.SoftwareChanged(tenantID, res.ChangedAssets)
	}
}

// resolveSoftware turns observations into links: identity and version
// parsed, products resolved in one pass, versions created once per report.
func (s *Service) resolveSoftware(ctx context.Context, tenantID shared.ID, work []softwareWork) ([]software.Link, error) {
	type item struct {
		assetID shared.ID
		obs     software.Observation
		parsed  software.Parsed
	}
	items := make([]item, 0, len(work))
	ids := make([]software.Identity, 0, len(work))
	for _, w := range work {
		for _, o := range w.obs {
			p, ok := software.Parse(o)
			if !ok {
				continue
			}
			items = append(items, item{assetID: w.assetID, obs: o, parsed: p})
			ids = append(ids, p.Identity)
		}
	}
	if len(items) == 0 {
		return nil, nil
	}
	refs, err := s.software.repo.Resolve(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	type versionKey struct {
		product shared.ID
		v       software.VersionKey
	}
	versions := map[versionKey]shared.ID{}
	type linkKey struct {
		asset, version shared.ID
		location       string
	}
	byKey := map[linkKey]int{}
	links := make([]software.Link, 0, len(items))
	for _, it := range items {
		ref, ok := refs[it.parsed.Identity]
		if !ok {
			continue
		}
		vk := versionKey{product: ref.ID, v: it.parsed.Version}
		vid, ok := versions[vk]
		if !ok {
			vid, err = s.software.repo.EnsureVersion(ctx, tenantID, ref, it.parsed.Version)
			if err != nil {
				return nil, err
			}
			versions[vk] = vid
		}
		l := software.Link{
			AssetID: it.assetID, ProductID: ref.ID, VersionID: vid,
			Location: it.obs.Location, Port: it.obs.Port, Transport: it.obs.Transport,
			Source: it.obs.Source, Evidence: it.obs.Evidence,
			Confidence: software.Confidence(it.parsed, it.obs, ref.Global),
		}
		k := linkKey{asset: it.assetID, version: vid, location: l.Location}
		if i, seen := byKey[k]; seen {
			if l.Confidence > links[i].Confidence {
				links[i] = l
			}
			continue
		}
		byKey[k] = len(links)
		links = append(links, l)
	}
	return links, nil
}

// softwareObservations reads every product a CTIS asset says it runs.
func softwareObservations(a *ctis.Asset) []software.Observation {
	out := make([]software.Observation, 0, len(a.Technologies)+len(a.Services)+2)
	for _, t := range a.Technologies {
		out = append(out, software.Observation{
			Name: t.Name, Version: t.Version, CPE: t.CPE, Source: software.SourceTechnology,
			Evidence: evidenceOf(t.Name, t.Version), ToolConfidence: t.Confidence,
		})
	}
	for _, sv := range a.Services {
		transport := normTransport(sv.Protocol)
		loc := ""
		if sv.Port > 0 && sv.Port <= 65535 {
			loc = transport + "/" + strconv.Itoa(sv.Port)
		}
		base := software.Observation{Port: sv.Port, Transport: transport, Location: loc, Source: software.SourceService}
		out = append(out, productObservations(base, sv.Product, sv.Version, sv.CPE, sv.Banner)...)
	}
	if a.Technical != nil && a.Technical.Service != nil {
		svc := a.Technical.Service
		base := software.Observation{Port: svc.Port, Transport: normTransport(svc.Transport), Source: software.SourceService}
		out = append(out, productObservations(base, svc.Product, svc.Version, svc.CPE, svc.Banner)...)
	}
	if a.IdentityHints != nil && a.IdentityHints.OSCPE != "" {
		out = append(out, software.Observation{CPE: a.IdentityHints.OSCPE, Source: software.SourceOS, Evidence: a.IdentityHints.OSCPE})
	}
	out = append(out, propertyObservations(a)...)
	return out
}

// productObservations is one service's product: its CPE or name and
// version, or failing those the products its banner names.
func productObservations(base software.Observation, product, version, cpe, banner string) []software.Observation {
	switch {
	case strings.TrimSpace(product) != "" || strings.TrimSpace(cpe) != "":
		o := base
		o.Name, o.Version, o.CPE = product, version, cpe
		o.Evidence = firstNonEmptyStr(banner, evidenceOf(product, version), cpe)
		return []software.Observation{o}
	case strings.TrimSpace(banner) != "":
		var out []software.Observation
		for _, b := range software.ParseBanner(banner) {
			o := base
			o.Name, o.Version, o.Evidence = b.Name, b.Version, banner
			out = append(out, o)
		}
		return out
	}
	return nil
}

// propertyObservations reads the loose property keys producers use:
// technologies ("Name:version"), the HTTP Server header, and an open port's
// service and version.
func propertyObservations(a *ctis.Asset) []software.Observation {
	if len(a.Properties) == 0 {
		return nil
	}
	out := make([]software.Observation, 0, 4)
	for _, key := range []string{"technologies", "technology"} {
		for _, t := range stringList(a.Properties[key]) {
			name, version := software.SplitTechnology(t)
			out = append(out, software.Observation{Name: name, Version: version, Source: software.SourceTechnology, Evidence: t})
		}
	}
	for _, key := range []string{"server", "web_server"} {
		if v, ok := a.Properties[key].(string); ok && strings.TrimSpace(v) != "" {
			for _, b := range software.ParseBanner(v) {
				out = append(out, software.Observation{Name: b.Name, Version: b.Version, Source: software.SourceService, Evidence: v})
			}
		}
	}
	if a.Type == ctis.AssetTypeOpenPort {
		version, _ := a.Properties["version"].(string)
		service, _ := a.Properties["service"].(string)
		transport := ""
		if p, ok := a.Properties["protocol"].(string); ok {
			transport = normTransport(p)
		}
		base := software.Observation{Transport: transport, Source: software.SourceOpenPort}
		switch banners := software.ParseBanner(version); {
		case len(banners) > 0:
			for _, b := range banners {
				o := base
				o.Name, o.Version, o.Evidence = b.Name, b.Version, version
				out = append(out, o)
			}
		case service != "":
			o := base
			o.Name, o.Version, o.Evidence = service, version, evidenceOf(service, version)
			out = append(out, o)
		}
	}
	return out
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t != "" {
			return []string{t}
		}
	}
	return nil
}

func normTransport(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "udp":
		return "udp"
	case "sctp":
		return "sctp"
	case "tcp", "":
		return "tcp"
	}
	return "tcp"
}

func evidenceOf(name, version string) string {
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if version == "" {
		return name
	}
	return fmt.Sprintf("%s %s", name, version)
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

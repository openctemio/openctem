package ingest

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/assettech"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/software"
	"github.com/openctemio/openctem/server/pkg/logger"
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

// SetSoftwareChangeSink wires the matcher's queue of changed assets, for
// technology observations and for dependency (package) reports.
func (s *Service) SetSoftwareChangeSink(sink SoftwareChangeSink) {
	if s.software != nil {
		s.software.sink = sink
	}
	if s.componentProcessor != nil {
		s.componentProcessor.SetSoftwareChangeSink(sink)
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
	observedAt := reportObservedAt(report, time.Now())
	links, err := s.resolveSoftware(ctx, tenantID, work, observedAt)
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

// resolveSoftware turns observations into links (software.BuildLinks).
func (s *Service) resolveSoftware(ctx context.Context, tenantID shared.ID, work []softwareWork, observedAt time.Time) ([]software.Link, error) {
	n := 0
	for _, w := range work {
		n += len(w.obs)
	}
	obs := make([]software.AssetObservation, 0, n)
	for _, w := range work {
		for _, o := range w.obs {
			obs = append(obs, software.AssetObservation{AssetID: w.assetID, Obs: o, ObservedAt: observedAt})
		}
	}
	return software.BuildLinks(ctx, s.software.repo, tenantID, obs)
}

// softwareObservations reads every product a CTIS asset says it runs.
func softwareObservations(a *ctis.Asset) []software.Observation {
	out := make([]software.Observation, 0, len(a.Technologies)+3)
	for _, t := range a.Technologies {
		// A detection is a component only when it names a real product
		// with a version or CPE, or a curated public product whose version
		// is hidden (RFC-112, IsSoftwareCandidate); the rest stay asset
		// technologies.
		if !assettech.IsSoftwareCandidate(t.Name, t.Version, t.CPE, t.Categories) {
			continue
		}
		out = append(out, software.Observation{
			Name: t.Name, Version: t.Version, CPE: t.CPE, Source: software.SourceTechnology,
			Evidence: evidenceOf(t.Name, t.Version), ToolConfidence: t.Confidence,
		})
	}
	if a.Technical != nil && a.Technical.Service != nil {
		svc := a.Technical.Service
		transport := normTransport(string(svc.Transport))
		loc := ""
		if svc.Port > 0 && svc.Port <= 65535 {
			loc = transport + "/" + strconv.Itoa(svc.Port)
		}
		base := software.Observation{Port: svc.Port, Transport: transport, Location: loc, Source: software.SourceService}
		if a.Type == ctis.AssetTypeService {
			// The service asset of an open port.
			base.Source = software.SourceOpenPort
		}
		out = append(out, productObservations(base, svc.Product, svc.Version, svc.CPE, svc.Banner)...)
	}
	// The HTTP Server header of a web origin.
	if a.Technical != nil && a.Technical.HTTP != nil && strings.TrimSpace(a.Technical.HTTP.WebServer) != "" {
		v := a.Technical.HTTP.WebServer
		banners := software.ParseBanner(v)
		for _, b := range banners {
			out = append(out, software.Observation{Name: b.Name, Version: b.Version, Source: software.SourceService, Evidence: v})
		}
		if len(banners) == 0 && software.IsCuratedAppName(v) {
			// "Server: nginx" with the version hidden: the product is known.
			out = append(out, software.Observation{Name: strings.TrimSpace(v), Source: software.SourceService, Evidence: v})
		}
	}
	if a.IdentityHints != nil && a.IdentityHints.OSCPE != "" {
		out = append(out, software.Observation{CPE: a.IdentityHints.OSCPE, Source: software.SourceOS, Evidence: a.IdentityHints.OSCPE})
	}
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
		// The tool fingerprinted the service (product and version from its
		// probes), not only read a banner.
		o.Class = software.ClassProbe
		return []software.Observation{o}
	case strings.TrimSpace(banner) != "":
		var out []software.Observation
		for _, b := range software.ParseBanner(banner) {
			o := base
			o.Name, o.Version, o.Evidence = b.Name, b.Version, banner
			o.Class = software.ClassBanner
			out = append(out, o)
		}
		return out
	}
	return nil
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

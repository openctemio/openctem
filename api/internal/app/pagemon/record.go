package pagemon

import (
	"context"
	"net/url"
	"strings"

	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RecordReport takes the fetches of one report. A fetch counts only for an
// enabled watch of the report's tenant (a sensor cannot plant content for a
// URL nobody watches). Best effort: a fetch that cannot be used is skipped
// and counted.
func (s *Service) RecordReport(ctx context.Context, tenantID shared.ID, tool string, items []pagemon.Item) (taken, skipped int) {
	now := s.now()
	budget := pagemon.MaxBodyBytesPerReport
	var caps []pagemon.Capture
	for _, it := range items {
		cs, bad := pagemon.FromProperty(it.Raw, tool, now, &budget)
		skipped += bad
		for _, c := range cs {
			if len(caps) >= pagemon.MaxCapturesPerReport {
				skipped++
				continue
			}
			caps = append(caps, c)
		}
	}
	if len(caps) == 0 {
		return 0, skipped
	}
	urls := make([]string, 0, len(caps))
	for _, c := range caps {
		urls = append(urls, c.URL)
	}
	watches, err := s.store.EnabledWatchesByURL(ctx, tenantID, urls)
	if err != nil {
		s.log.Warn("page monitoring: watches unreadable; fetches dropped", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return 0, skipped + len(caps)
	}
	done := map[string]bool{}
	for _, c := range caps {
		w, ok := watches[c.URL]
		if !ok || done[c.URL] {
			skipped++
			continue
		}
		done[c.URL] = true
		if err := s.recordOne(ctx, tenantID, w, c); err != nil {
			s.log.Warn("page monitoring: fetch not recorded", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
			skipped++
			continue
		}
		taken++
	}
	return taken, skipped
}

func (s *Service) recordOne(ctx context.Context, tenantID shared.ID, w pagemon.Watch, c pagemon.Capture) error {
	out := pagemon.FetchOutcome{WatchID: w.ID, FetchedAt: c.FetchedAt, Status: c.StatusCode, Dynamic: w.Dynamic}
	if !c.OK() {
		out.Failed, out.ChangeStreak = true, w.ChangeStreak
		return s.store.SaveFetch(ctx, tenantID, out)
	}
	known, err := s.knownHosts(ctx, tenantID, c)
	if err != nil {
		return err
	}
	snap := pagemon.Build(c, w, known)
	snap.ID = shared.NewID()
	prev, err := s.store.LatestSnapshot(ctx, tenantID, w.ID)
	if err != nil {
		return err
	}
	var diff pagemon.Diff
	switch {
	case prev == nil: // baseline: no change, no alert
		out.Snapshot = &snap
	case prev.ContentHash == snap.ContentHash:
	default:
		d, sum, sev := pagemon.Compare(*prev, snap)
		diff = d
		out.ChangeStreak = w.ChangeStreak + 1
		out.Dynamic = w.Dynamic || out.ChangeStreak >= pagemon.DynamicAfter
		out.Snapshot, out.Diff = &snap, &diff
		out.Change = &pagemon.Change{
			ID: shared.NewID(), WatchID: w.ID, AssetID: w.AssetID, URL: w.URL, DetectedAt: c.FetchedAt,
			Severity: sev, Muted: out.Dynamic, Summary: sum,
		}
	}
	if err := s.store.SaveFetch(ctx, tenantID, out); err != nil {
		return err
	}
	if snap.Kind == pagemon.KindHTML && w.Source != pagemon.SourceDerived {
		if err := s.reconcileDerived(ctx, tenantID, w, pagemon.DerivedScripts(snap)); err != nil {
			s.log.Warn("page monitoring: page scripts not tracked", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
	if out.Change != nil {
		s.alert(ctx, tenantID, w, snap, diff)
	}
	return nil
}

// knownHosts looks up, once per capture, which third-party-looking script
// hosts of a page are domain assets of the organization.
func (s *Service) knownHosts(ctx context.Context, tenantID shared.ID, c pagemon.Capture) (func(string) bool, error) {
	hosts := pagemon.ScriptHosts(c)
	page, _ := url.Parse(c.URL)
	var ask []string
	for _, h := range hosts {
		if page != nil && !pagemon.FirstParty(page.Hostname(), h, nil) {
			ask = append(ask, h)
		}
	}
	if len(ask) == 0 {
		return nil, nil
	}
	set, err := s.store.KnownHosts(ctx, tenantID, ask)
	if err != nil {
		return nil, err
	}
	return func(h string) bool { return set[h] }, nil
}

// reconcileDerived makes the page's derived script watches match its
// first-party scripts: one per script identity, URL kept current, gone
// scripts removed. Bounded by the organization's watch limit.
func (s *Service) reconcileDerived(ctx context.Context, tenantID shared.ID, page pagemon.Watch, scripts []pagemon.ScriptRef) error {
	children, err := s.store.ListChildren(ctx, tenantID, page.ID)
	if err != nil {
		return err
	}
	byID := map[string]pagemon.Watch{}
	for _, ch := range children {
		if u, perr := url.Parse(ch.URL); perr == nil {
			byID[pagemon.ScriptIdentity(u)] = ch
		}
	}
	want := map[string]bool{}
	var count int
	counted := false
	now := s.now()
	for _, sc := range scripts {
		want[sc.ID] = true
		u, err := pagemon.NormalizeURL(sc.Src)
		if err != nil {
			continue
		}
		if ch, ok := byID[sc.ID]; ok {
			if ch.URL != u {
				ch.URL, ch.UpdatedAt = u, now
				if err := s.store.UpdateWatch(ctx, &ch); err != nil {
					return err
				}
			}
			continue
		}
		if !counted {
			if count, err = s.store.CountWatches(ctx, tenantID); err != nil {
				return err
			}
			counted = true
		}
		if count >= pagemon.MaxWatchesPerTenant {
			break
		}
		assetID, err := s.store.OriginAsset(ctx, tenantID, pagemon.OriginName(u))
		if err != nil {
			continue // a script on an origin the inventory does not have yet
		}
		pid := page.ID
		ch := &pagemon.Watch{
			ID: shared.NewID(), TenantID: tenantID, AssetID: assetID, ParentID: &pid, URL: u, Mode: pagemon.ModeJS,
			Source: pagemon.SourceDerived, Enabled: true, CadenceHours: page.CadenceHours, IgnorePatterns: page.IgnorePatterns,
			State: pagemon.StatePending, NextDueAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := s.store.CreateWatch(ctx, ch); err != nil {
			continue // already watched on its own
		}
		count++
	}
	for id, ch := range byID {
		if !want[id] {
			if err := s.store.DeleteWatch(ctx, tenantID, ch.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// ThirdPartyFingerprint is the exposure identity of a third-party script
// host on a page.
func ThirdPartyFingerprint(tenantID shared.ID, pageURL, host string) string {
	return exposuredom.Fingerprint(tenantID.String(), string(exposuredom.EventTypeThirdPartyScriptAdded), "third_party_script", Source, "",
		map[string]any{"url": pageURL, "domain": host})
}

// alert raises an exposure per new third-party script host and resolves the
// ones for hosts the page stopped loading.
func (s *Service) alert(ctx context.Context, tenantID shared.ID, w pagemon.Watch, snap pagemon.Snapshot, d pagemon.Diff) {
	if s.exposures == nil {
		return
	}
	events := make([]*exposuredom.ExposureEvent, 0, len(d.NewThirdPartyHosts))
	fps := make([]string, 0, len(d.NewThirdPartyHosts))
	for _, h := range d.NewThirdPartyHosts {
		var srcs []string
		for _, sc := range snap.Scripts {
			if sc.Host == h && len(srcs) < 10 {
				srcs = append(srcs, sc.Src)
			}
		}
		ev, err := exposuredom.NewExposureEvent(tenantID, exposuredom.EventTypeThirdPartyScriptAdded, exposuredom.SeverityHigh,
			"New third-party script on "+clipTitle(w.URL)+": "+h, Source, map[string]any{
				"url": w.URL, "domain": h, "scripts": srcs, "watch_id": w.ID.String(),
			})
		if err != nil {
			continue
		}
		aid := w.AssetID
		ev.SetAssetID(&aid)
		fp := ThirdPartyFingerprint(tenantID, w.URL, h)
		ev.UseFingerprint(fp)
		events = append(events, ev)
		fps = append(fps, fp)
	}
	if len(events) > 0 {
		if err := s.exposures.BulkUpsert(ctx, events); err != nil {
			s.log.Warn("page monitoring: exposure not written", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		} else if s.resolver != nil {
			// A host that comes back reopens what the monitor itself resolved.
			_, _ = s.resolver.ReopenAuto(ctx, tenantID, Source, fps, goneNote)
		}
	}
	if s.resolver != nil && len(d.GoneThirdPartyHosts) > 0 {
		gone := make([]string, 0, len(d.GoneThirdPartyHosts))
		for _, h := range d.GoneThirdPartyHosts {
			gone = append(gone, ThirdPartyFingerprint(tenantID, w.URL, h))
		}
		if _, err := s.resolver.ResolveAuto(ctx, tenantID, Source, gone, goneNote); err != nil {
			s.log.Warn("page monitoring: exposures not resolved", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
}

func clipTitle(u string) string {
	if len(u) <= 200 {
		return u
	}
	return strings.ToValidUTF8(u[:200], "") + "..."
}

package certmonitor

// Rejection hygiene for CT exposures (research/22 P0-9, bug 22c B2):
//
//   - a name a person rejected (a live tombstone, or an asset whose
//     attribution is rejected), or any name under one, produces no CT
//     exposure;
//   - a CT exposure's identity does not depend on which asset it is linked
//     to, so linking it to its own subdomain asset (or the root's asset once
//     one exists) updates the row instead of creating a duplicate;
//   - a CT exposure is linked to the host's own asset when there is one.
//
// Design: docs/rfcs/RFC-036-easm.md; docs/architecture/certificate-transparency-monitoring.md.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ExposureRelinker updates the asset a stored exposure is linked to, for
// the tenant's exposures of one source (*postgres.ExposureRepository).
type ExposureRelinker interface {
	RelinkExposures(ctx context.Context, tenantID shared.ID, source string, links map[string]shared.ID) (int, error)
}

// SetRelinker wires relinking of stored CT exposures to their host's asset
// (nil: stored rows keep their link; new rows are still linked right).
func (s *Service) SetRelinker(r ExposureRelinker) { s.relinker = r }

// ctFingerprint is the identity of a CT exposure: tenant, type, title and
// host, never the linked asset. Migration 001018 re-keys stored rows to it.
func ctFingerprint(tenantID shared.ID, ev *exposuredom.ExposureEvent, host string) string {
	return exposuredom.Fingerprint(tenantID.String(), ev.EventType().String(), ev.Title(), Source, "",
		map[string]any{"domain": host})
}

// rootFinds is one root's CT result, kept until promotion has run.
type rootFinds struct {
	root rootDomain
	d    discoveries
}

// hostsOf lists every host a sweep's results mention.
func hostsOf(found []rootFinds) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, f := range found {
		for _, h := range f.d.subdomains {
			add(h)
		}
		for _, c := range f.d.expiring {
			add(c.Host)
		}
		for _, c := range f.d.expired {
			add(c.Host)
		}
	}
	return out
}

// selfAndParentsUnder returns host and its parents down to (and including)
// the first public-suffix boundary parentOf stops at.
func selfAndParentsUnder(host string) []string {
	out := []string{host}
	for p := parentOf(host); p != ""; p = parentOf(p) {
		out = append(out, p)
	}
	return out
}

// hostAssets returns, for the given hosts, the tenant's asset of that exact
// name and the hosts that are rejected (themselves or a parent: a live
// tombstone or an asset whose attribution is rejected). Without promotion
// wired it finds nothing and rejects nothing.
func (s *Service) hostAssets(ctx context.Context, tenantID shared.ID, hosts []string) (map[string]shared.ID, map[string]bool, error) {
	own := map[string]shared.ID{}
	rejected := map[string]bool{}
	if s.assetNames == nil || len(hosts) == 0 {
		return own, rejected, nil
	}
	seen := map[string]bool{}
	var names []string
	for _, h := range hosts {
		for _, n := range selfAndParentsUnder(h) {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	assets, err := s.assetNames.GetByNames(ctx, tenantID, names)
	if err != nil {
		return nil, nil, fmt.Errorf("look up CT hosts: %w", err)
	}
	dead := map[string]bool{}
	if s.tombstones != nil {
		tombs, err := s.tombstones.Tombstoned(ctx, tenantID, names)
		if err != nil {
			return nil, nil, fmt.Errorf("look up tombstones: %w", err)
		}
		for n := range tombs {
			dead[n] = true
		}
	}
	if s.attribution != nil && len(assets) > 0 {
		ids := make([]string, 0, len(assets))
		nameOf := map[string]string{}
		for n, a := range assets {
			if a != nil {
				ids = append(ids, a.ID().String())
				nameOf[a.ID().String()] = n
			}
		}
		recs, err := s.attribution.Records(ctx, tenantID, ids)
		if err != nil {
			return nil, nil, fmt.Errorf("look up attribution of CT hosts: %w", err)
		}
		for id, r := range recs {
			if r.State == attribution.StateRejected {
				dead[nameOf[id]] = true
			}
		}
	}
	for _, h := range hosts {
		if a, ok := assets[h]; ok && a != nil {
			own[h] = a.ID()
		}
		for _, n := range selfAndParentsUnder(h) {
			if dead[n] {
				rejected[h] = true
				break
			}
		}
	}
	return own, rejected, nil
}

// withoutRejected drops rejected hosts from one root's results.
func withoutRejected(d discoveries, rejected map[string]bool) (discoveries, int) {
	if len(rejected) == 0 {
		return d, 0
	}
	dropped := 0
	subs := d.subdomains[:0:0]
	for _, h := range d.subdomains {
		if rejected[h] {
			dropped++
			continue
		}
		subs = append(subs, h)
	}
	keep := func(in []expiringCert) []expiringCert {
		out := in[:0:0]
		for _, c := range in {
			if rejected[c.Host] {
				dropped++
				continue
			}
			out = append(out, c)
		}
		return out
	}
	d.subdomains = subs
	d.expiring = keep(d.expiring)
	d.expired = keep(d.expired)
	return d, dropped
}

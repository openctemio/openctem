package software

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// AssetObservation is one product an asset was seen running, and when.
type AssetObservation struct {
	AssetID    shared.ID
	Obs        Observation
	ObservedAt time.Time
}

// BuildLinks turns observations into links: identity and version parsed,
// products resolved in one pass, each version created once. Observations
// that name nothing usable are skipped. Two observations of one asset,
// version and location become one link, the stronger evidence kept.
func BuildLinks(ctx context.Context, repo Repository, tenantID shared.ID, obs []AssetObservation) ([]Link, error) {
	type item struct {
		AssetObservation
		parsed Parsed
	}
	items := make([]item, 0, len(obs))
	ids := make([]Identity, 0, len(obs))
	for _, o := range obs {
		p, ok := Parse(o.Obs)
		if !ok {
			continue
		}
		items = append(items, item{AssetObservation: o, parsed: p})
		ids = append(ids, p.Identity)
	}
	if len(items) == 0 {
		return nil, nil
	}
	refs, err := repo.Resolve(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	type versionKey struct {
		product shared.ID
		v       VersionKey
	}
	versions := map[versionKey]shared.ID{}
	type linkKey struct {
		asset, version shared.ID
		location       string
	}
	byKey := map[linkKey]int{}
	links := make([]Link, 0, len(items))
	for _, it := range items {
		ref, ok := refs[it.parsed.Identity]
		if !ok {
			continue
		}
		vk := versionKey{product: ref.ID, v: it.parsed.Version}
		vid, ok := versions[vk]
		if !ok {
			vid, err = repo.EnsureVersion(ctx, tenantID, ref, it.parsed.Version)
			if err != nil {
				return nil, err
			}
			versions[vk] = vid
		}
		l := Link{
			AssetID: it.AssetID, ProductID: ref.ID, VersionID: vid,
			Location: it.Obs.Location, Port: it.Obs.Port, Transport: it.Obs.Transport,
			Source: it.Obs.Source, Evidence: it.Obs.Evidence,
			Confidence: Confidence(it.parsed, it.Obs, ref.Global),
			Version:    it.parsed.Version, Segments: it.parsed.Segments,
			Class: ClassOf(it.Obs, it.parsed), ObservedAt: it.ObservedAt,
		}
		k := linkKey{asset: it.AssetID, version: vid, location: l.Location}
		if i, seen := byKey[k]; seen {
			if l.Class.Rank() > links[i].Class.Rank() ||
				(l.Class == links[i].Class && l.Confidence > links[i].Confidence) {
				links[i] = l
			}
			continue
		}
		byKey[k] = len(links)
		links = append(links, l)
	}
	return links, nil
}

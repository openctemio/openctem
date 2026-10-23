package vulnmatch

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// MatchIdentity is the identity a match's finding is keyed on.
//
// A match on a package link uses the package identity scanners use for the
// same issue: (asset, package URL without version, CVE). A scanner report
// and a version match for one package and CVE are then one finding, and a
// scanner finding a person closed is not created again by the matcher.
// legacy is the network identity such a match was keyed on before;
// reconcile uses it to move the matcher's findings stored under it.
//
// Any other match (a technology, service or OS product named by CPE) keeps
// the network identity (asset, CVE, port) that network scanners use.
func MatchIdentity(m softwarematch.Match) (key vulnerability.IdentityKey, legacy *vulnerability.IdentityKey, ok bool) {
	network, netOK := vulnerability.NetworkIdentity(m.AssetID.String(), m.Result.CVEID, "", m.Port, m.Transport)
	if purl := PackageIdentityPURL(m); purl != "" {
		if k, ok := vulnerability.SCAIdentity(m.AssetID.String(), purl, "", "", m.Result.CVEID, ""); ok {
			if netOK {
				legacy = &network
			}
			return k, legacy, true
		}
	}
	return network, nil, netOK
}

// PackageIdentityPURL is the package URL a package match is keyed on: the
// linked version's package URL and, for an OS package, the distro of the
// version's build qualifier (the finding identity keeps the distro of deb,
// rpm and apk packages). "" when the match is not on a package link or the
// version has no package URL.
func PackageIdentityPURL(m softwarematch.Match) string {
	p := strings.TrimSpace(m.PURL)
	if !m.Package || p == "" || vulnerability.CanonicalPURLIdentity(p) == "" {
		return ""
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if d := software.DistroFromQualifier(m.Qualifier); d != "" {
		p += "?distro=" + url.QueryEscape(d)
	}
	return p
}

// adoptLegacyKeys moves the matcher's own findings of package matches from
// the legacy network key to the package key, when no finding holds the
// package key yet; the old key stays an alias (database trigger). When
// another finding holds the package key, the legacy finding keeps its key
// and the candidate goes back to it: two findings are never merged here
// (a person can mark one a duplicate). Returns the fingerprints moved.
func (s *Service) adoptLegacyKeys(ctx context.Context, tenantID shared.ID, desired map[string]*candidate,
	byFP map[string]softwarematch.MatcherFinding, st *Stats,
) ([]string, error) {
	fps := make([]string, 0, len(desired))
	for fp, c := range desired {
		if c.legacy != nil {
			fps = append(fps, fp)
		}
	}
	sort.Strings(fps) // deterministic when two packages share one legacy key
	var moved []string
	for _, fp := range fps {
		c := desired[fp]
		if _, ok := byFP[fp]; ok {
			continue
		}
		from := c.legacy.Fingerprint()
		old, ok := byFP[from]
		if !ok {
			continue
		}
		raw, err := vulnerability.MarshalIdentityKey(c.key)
		if err != nil {
			return moved, err
		}
		done, err := s.store.RekeyMatcherFinding(ctx, tenantID, softwarematch.Rekey{
			FindingID: old.ID, From: from, To: fp, Version: c.key.Version, IdentityKey: raw, ComponentID: c.m.VersionID,
		})
		if err != nil {
			return moved, err
		}
		if done {
			delete(byFP, from)
			old.Fingerprint = fp
			byFP[fp] = old
			moved = append(moved, fp)
			st.Rekeyed++
			continue
		}
		delete(desired, fp)
		c.key, c.legacy = *c.legacy, nil
		if prev, ok := desired[from]; !ok || prev.confidence < c.confidence {
			desired[from] = c
		}
	}
	return moved, nil
}

// applyVEX applies the organization's VEX statements to the findings the
// pass created or re-keyed. Best-effort, like ingest: a failure is logged
// and the next statement change or sighting applies them.
func (s *Service) applyVEX(ctx context.Context, tenantID shared.ID, fingerprints []string) {
	if s.vex == nil || len(fingerprints) == 0 {
		return
	}
	if _, err := s.vex.ApplyToFingerprints(ctx, tenantID, fingerprints); err != nil {
		s.logger.Warn("vulnerability matching: VEX statements not applied", "tenant_id", tenantID.String(), "error", err)
	}
}

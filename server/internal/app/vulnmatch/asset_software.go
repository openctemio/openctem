package vulnmatch

import (
	"context"
	"errors"
	"sort"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// LinkReader lists an asset's software links.
type LinkReader interface {
	ListAssetLinks(ctx context.Context, tenantID, assetID shared.ID) ([]software.AssetLink, error)
}

// SetLinkReader wires the asset software list.
func (s *Service) SetLinkReader(r LinkReader) { s.links = r }

// ErrNoLinkReader is returned when the list is not wired.
var ErrNoLinkReader = errors.New("asset software list not wired")

// SoftwareItem is one product an asset runs with the CVEs its version falls
// in, scored as the matcher scores them.
type SoftwareItem struct {
	Link    software.AssetLink
	Stale   bool // not seen for StaleAfter
	Matches []ScoredMatch
}

// ScoredMatch is one CVE of a software item.
type ScoredMatch struct {
	CVEID       string
	Severity    string
	CVSSScore   *float64
	InKEV       bool
	EPSS        float64
	Confidence  int
	Label       vulnmatch.Label
	Range       string
	Reasons     []string
	AllVersions bool
	// InPolicy: the match passes the organization's policy, so it is (or
	// will be on the next pass) a finding.
	InPolicy bool
}

// AssetSoftware lists what the asset runs and the CVEs that match it. The
// caller has already checked that it may see the asset.
func (s *Service) AssetSoftware(ctx context.Context, tenantID, assetID shared.ID) ([]SoftwareItem, error) {
	if s.links == nil {
		return nil, ErrNoLinkReader
	}
	links, err := s.links.ListAssetLinks(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	matches, err := s.store.AssetMatches(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	policy, err := s.policy.VulnMatchingPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	type key struct {
		version  shared.ID
		location string
	}
	byLink := map[key][]softwarematch.Match{}
	for _, m := range matches {
		k := key{m.VersionID, m.Location}
		byLink[k] = append(byLink[k], m)
	}
	staleBefore := s.now().Add(-softwarematch.StaleAfter)
	out := make([]SoftwareItem, 0, len(links))
	for _, l := range links {
		item := SoftwareItem{Link: l, Stale: l.LastSeen.Before(staleBefore)}
		for _, m := range byLink[key{l.VersionID, l.Location}] {
			res := vulnmatch.Result{VulnID: m.Result.CVEID, AllVersions: m.Result.AllVersions,
				Adjustment: m.Result.Adjustment, Reasons: m.Result.Reasons}
			if m.Result.ConditionProductID != nil {
				res.Range.Condition = m.Result.ConditionProductID.String()
			}
			conf, label, reasons := vulnmatch.Confidence(m.LinkConfidence, res, m.ConditionMet)
			item.Matches = append(item.Matches, ScoredMatch{
				CVEID: m.Result.CVEID, Severity: m.CVE.Severity, CVSSScore: m.CVE.CVSSScore,
				InKEV: m.CVE.InKEV, EPSS: m.CVE.EPSS, Confidence: conf, Label: label,
				Range: m.Result.RangeText, Reasons: reasons, AllVersions: m.Result.AllVersions,
				InPolicy: policy.Enabled && !item.Stale && Passes(policy, m, res, conf),
			})
		}
		sort.SliceStable(item.Matches, func(i, j int) bool {
			a, b := item.Matches[i], item.Matches[j]
			if a.InPolicy != b.InPolicy {
				return a.InPolicy
			}
			return a.Confidence > b.Confidence
		})
		out = append(out, item)
	}
	return out, nil
}

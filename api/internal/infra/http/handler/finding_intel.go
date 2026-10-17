package handler

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingIntel is the vulnerability intelligence of a finding with its
// sources and freshness: what the scanner's advisory said (kept on the
// finding, since a report never writes the shared catalog) and the date of
// the feed values the finding carries (EPSS, CISA KEV). Producer text:
// clients render it escaped; references are http(s) only.
type FindingIntel struct {
	// CVSSSource names who scored the primary CVSS (nvd, ghsa, a vendor).
	CVSSSource  string     `json:"cvss_source,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	ModifiedAt  *time.Time `json:"modified_at,omitempty"`
	References  []string   `json:"references,omitempty"`
	// EPSSDate is the day of the EPSS score the finding carries (YYYY-MM-DD).
	EPSSDate string `json:"epss_date,omitempty"`
	// KEVDateAdded is when CISA added the CVE to KEV (YYYY-MM-DD).
	KEVDateAdded  string `json:"kev_date_added,omitempty"`
	KEVRansomware bool   `json:"kev_ransomware,omitempty"`
}

// EPSSFeed and KEVFeed read the global threat-intel feeds by CVE. They hold
// public data, not tenant data, and are reached only through a finding the
// caller may read.
type EPSSFeed interface {
	GetByCVEID(ctx context.Context, cveID string) (*threatintel.EPSSScore, error)
}

// KEVFeed reads the CISA KEV catalog by CVE.
type KEVFeed interface {
	GetByCVEID(ctx context.Context, cveID string) (*threatintel.KEVEntry, error)
}

// SetIntelFeeds wires the EPSS and KEV lookups for the single-finding
// response. Safe after construction; nil leaves the feed dates out.
func (h *VulnerabilityHandler) SetIntelFeeds(epss EPSSFeed, kev KEVFeed) {
	h.epssFeed, h.kevFeed = epss, kev
}

const intelDateFormat = "2006-01-02"

// enrichFindingWithIntel fills resp.Intel; it is left nil when there is
// nothing to say.
func (h *VulnerabilityHandler) enrichFindingWithIntel(ctx context.Context, f *vulnerability.Finding, resp *FindingResponse) {
	meta := f.Metadata()
	in := FindingIntel{
		CVSSSource:  stringMeta(meta, vulnerability.FindingMetaCVSSSource),
		PublishedAt: vulnerability.MetaTime(meta, vulnerability.FindingMetaPublishedAt),
		ModifiedAt:  vulnerability.MetaTime(meta, vulnerability.FindingMetaModifiedAt),
		References:  vulnerability.NormalizeReferences(vulnerability.MetaStrings(meta, vulnerability.FindingMetaReferences)),
	}
	if cve := f.CVEID(); cve != "" {
		if h.epssFeed != nil && f.EPSSScore() != nil {
			if e, err := h.epssFeed.GetByCVEID(ctx, cve); err == nil && e != nil && !e.ScoreDate().IsZero() {
				in.EPSSDate = e.ScoreDate().UTC().Format(intelDateFormat)
			}
		}
		if h.kevFeed != nil && f.IsInKEV() {
			if k, err := h.kevFeed.GetByCVEID(ctx, cve); err == nil && k != nil {
				if !k.DateAdded().IsZero() {
					in.KEVDateAdded = k.DateAdded().UTC().Format(intelDateFormat)
				}
				in.KEVRansomware = k.HasRansomwareUse()
			}
		}
	}
	if in.CVSSSource == "" && in.PublishedAt == nil && in.ModifiedAt == nil && len(in.References) == 0 &&
		in.EPSSDate == "" && in.KEVDateAdded == "" {
		return
	}
	resp.Intel = &in
}

func stringMeta(meta map[string]any, key string) string {
	s, _ := meta[key].(string)
	return s
}

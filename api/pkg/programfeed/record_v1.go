package programfeed

import (
	"fmt"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// V1 reads records of schema openctem.programfeed/v1, one program per line:
//
//	{"id": "acme-bounty:acme", "platform": "acme-bounty", "handle": "acme",
//	 "name": "Acme", "url": "https://…", "offers_bounty": true, "open": true,
//	 "in_scope": [{"identifier": "*.acme.example", "type": "wildcard"}],
//	 "out_of_scope": [{"identifier": "admin.acme.example"}],
//	 "rules": {"rate_limit_rps": 5, "forbidden": ["dos"]},
//	 "terms_text": "…", "source": "…", "as_of": "2026-10-10T00:00:00Z"}
//
// Unknown fields are refused, so a schema change cannot be read silently.
type V1 struct{}

type v1Target struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type,omitempty"`
}

type v1Record struct {
	ID           string     `json:"id"`
	Platform     string     `json:"platform"`
	Handle       string     `json:"handle"`
	Name         string     `json:"name"`
	URL          string     `json:"url"`
	OffersBounty bool       `json:"offers_bounty"`
	Open         bool       `json:"open"`
	InScope      []v1Target `json:"in_scope"`
	OutOfScope   []v1Target `json:"out_of_scope"`
	Rules        bp.Rules   `json:"rules"`
	TermsText    string     `json:"terms_text"`
	Source       string     `json:"source"`
	AsOf         time.Time  `json:"as_of"`
}

// Parse reads one record.
func (V1) Parse(line []byte) (bp.PublicProgram, error) {
	var r v1Record
	if err := feedsign.DecodeStrict(line, &r); err != nil {
		return bp.PublicProgram{}, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	if len(r.InScope)+len(r.OutOfScope) > bp.MaxScopeItems {
		return bp.PublicProgram{}, bp.ErrScopeTooLarge
	}
	items := make([]bp.Item, 0, len(r.InScope)+len(r.OutOfScope))
	for _, t := range r.InScope {
		it := bp.ClassifyTyped(t.Identifier, t.Type)
		it.InScope = true
		items = append(items, it)
	}
	for _, t := range r.OutOfScope {
		items = append(items, bp.ClassifyTyped(t.Identifier, t.Type))
	}
	return bp.PublicProgram{FeedID: r.ID, Platform: r.Platform, Handle: r.Handle, Name: r.Name, URL: r.URL,
		OffersBounty: r.OffersBounty, Open: r.Open, Items: items, Rules: r.Rules, TermsText: r.TermsText,
		Source: r.Source, AsOf: r.AsOf}, nil
}

package programfeed

import (
	"fmt"
	"strings"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// V1 reads records of schema openctem.programfeed/v1 (the collector's
// schema/program.schema.json and schema/change.schema.json). Unknown fields
// are refused, so a schema change cannot be read silently. Every target is
// classified again by the platform's own parser: the feed's canonical form
// is not trusted to be scannable.
type V1 struct{}

type v1Target struct {
	Type              string `json:"type"`
	Value             string `json:"value"`
	Confidence        string `json:"confidence"`
	EligibleForBounty *bool  `json:"eligible_for_bounty,omitempty"`
	MaxSeverity       string `json:"max_severity,omitempty"`
	Notes             string `json:"notes,omitempty"`
}

type v1Rejected struct {
	Scope  string `json:"scope"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

type v1Rules struct {
	Summary             string   `json:"summary,omitempty"`
	TestingRestrictions []string `json:"testing_restrictions"`
	RateLimit           string   `json:"rate_limit,omitempty"`
	RequiredHeaders     []string `json:"required_headers"`
	SafeHarbour         string   `json:"safe_harbour"` //nolint:misspell // the collector wire name
	DisclosureDays      int      `json:"disclosure_days,omitempty"`
	Languages           []string `json:"languages"`
}

type v1Terms struct {
	URL       string     `json:"url"`
	SHA256    string     `json:"sha256,omitempty"`
	FetchedAt *time.Time `json:"fetched_at,omitempty"`
}

type v1Contact struct {
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

type v1Provenance struct {
	Source           string    `json:"source"`
	SourceURL        string    `json:"source_url"`
	FetchedAt        time.Time `json:"fetched_at"`
	Dataset          string    `json:"dataset,omitempty"`
	DatasetCommit    string    `json:"dataset_commit,omitempty"`
	OriginalPlatform string    `json:"original_platform,omitempty"`
	OriginalURL      string    `json:"original_url,omitempty"`
}

type v1Record struct {
	ID             string       `json:"id"`
	Source         string       `json:"source"`
	Platform       string       `json:"platform"`
	Name           string       `json:"name"`
	URL            string       `json:"url"`
	Type           string       `json:"type"`
	Status         string       `json:"status"`
	OffersBounty   bool         `json:"offers_bounty"`
	ScopePublished bool         `json:"scope_published"`
	InScope        []v1Target   `json:"in_scope"`
	OutOfScope     []v1Target   `json:"out_of_scope"`
	Rejected       []v1Rejected `json:"rejected"`
	Rules          v1Rules      `json:"rules"`
	Terms          v1Terms      `json:"terms"`
	Contact        v1Contact    `json:"contact"`
	Provenance     v1Provenance `json:"provenance"`
	FirstSeen      time.Time    `json:"first_seen"`
	LastSeen       time.Time    `json:"last_seen"`
	LastChanged    time.Time    `json:"last_changed"`
	ClosedAt       *time.Time   `json:"closed_at,omitempty"`
}

type v1Change struct {
	Sequence uint64    `json:"sequence"`
	Program  string    `json:"program"`
	Kind     string    `json:"kind"`
	Scope    string    `json:"scope,omitempty"`
	Target   *v1Target `json:"target,omitempty"`
	Fields   []string  `json:"fields,omitempty"`
}

var v1ChangeKinds = map[string]bool{"program_added": true, "program_reopened": true, "status_changed": true,
	"program_modified": true, "rules_changed": true, "terms_changed": true, "target_added": true,
	"target_modified": true, "target_removed": true, "program_closed": true, "program_dropped": true}

// v1Label is the asset type label the classifier honors for a feed target
// type ("" for an unknown type).
func v1Label(feedType string) string {
	switch feedType {
	case "domain", "wildcard", "cidr", "url", "mobile_app", "other":
		return feedType
	case "source_repo":
		return "source_code"
	case "ip":
		return "ip_address"
	}
	return ""
}

func v1Item(t v1Target, inScope bool) (bp.Item, error) {
	label := v1Label(t.Type)
	if label == "" || len(t.Value) > 512 {
		return bp.Item{}, fmt.Errorf("%w: target type %q", shared.ErrValidation, t.Type)
	}
	it := bp.ClassifyTyped(t.Value, label)
	it.InScope, it.Confidence, it.AssetType = inScope, t.Confidence, t.Type
	return it, nil
}

// Parse reads one program record.
func (V1) Parse(line []byte) (bp.PublicProgram, error) {
	var r v1Record
	if err := feedsign.DecodeStrict(line, &r); err != nil {
		return bp.PublicProgram{}, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	if len(r.InScope) > bp.MaxScopeItems || len(r.OutOfScope) > bp.MaxScopeItems {
		return bp.PublicProgram{}, bp.ErrScopeTooLarge
	}
	if (r.Status == bp.FeedStatusClosed) != (r.ClosedAt != nil) || r.OffersBounty != (r.Type == "bounty") {
		return bp.PublicProgram{}, fmt.Errorf("%w: %s: status, closed_at, type and offers_bounty disagree", shared.ErrValidation, r.ID)
	}
	items := make([]bp.Item, 0, len(r.InScope)+len(r.OutOfScope))
	for _, t := range r.InScope {
		it, err := v1Item(t, true)
		if err != nil {
			return bp.PublicProgram{}, err
		}
		items = append(items, it)
	}
	for _, t := range r.OutOfScope {
		it, err := v1Item(t, false)
		if err != nil {
			return bp.PublicProgram{}, err
		}
		items = append(items, it)
	}
	headers, text := v1RulesText(r)
	return bp.PublicProgram{FeedID: r.ID, Source: r.Source, Platform: r.Platform, Name: r.Name, URL: r.URL,
		Type: r.Type, Status: r.Status, OffersBounty: r.OffersBounty, ScopePublished: r.ScopePublished,
		Items: items, Rules: bp.Rules{RequiredHeaders: headers}, TermsText: text, TermsURL: r.Terms.URL,
		TermsDocSHA256: r.Terms.SHA256, AsOf: r.LastSeen,
		Provenance: bp.FeedProvenance{Source: r.Provenance.Source, SourceURL: r.Provenance.SourceURL,
			FetchedAt: r.Provenance.FetchedAt, Dataset: r.Provenance.Dataset, DatasetCommit: r.Provenance.DatasetCommit,
			OriginalPlatform: r.Provenance.OriginalPlatform, OriginalURL: r.Provenance.OriginalURL}}, nil
}

// v1RulesText turns the feed's rules into the headers the platform can
// enforce (a "Name: value" header that passes the rules check; others stay
// text) and the terms text a person reads before accepting.
func v1RulesText(r v1Record) ([]bp.Header, string) {
	var headers []bp.Header
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}
	if r.Rules.Summary != "" {
		line("%s", r.Rules.Summary)
	}
	for _, x := range r.Rules.TestingRestrictions {
		line("- %s", x)
	}
	if r.Rules.RateLimit != "" {
		line("Rate limit: %s", r.Rules.RateLimit)
	}
	for _, h := range r.Rules.RequiredHeaders {
		name, value, ok := strings.Cut(h, ":")
		hdr := bp.Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)}
		if ok && len(headers) < bp.MaxHeaders && (bp.Rules{RequiredHeaders: []bp.Header{hdr}}).Validate() == nil {
			headers = append(headers, hdr)
		}
		line("Required header: %s", h)
	}
	if r.Rules.SafeHarbour != "" {
		line("Safe harbour: %s", r.Rules.SafeHarbour) //nolint:misspell // the collector wire name
	}
	if r.Rules.DisclosureDays > 0 {
		line("Disclosure after %d days", r.Rules.DisclosureDays)
	}
	if r.Terms.URL != "" {
		if r.Terms.SHA256 != "" {
			line("Terms: %s (sha256 %s)", r.Terms.URL, r.Terms.SHA256)
		} else {
			line("Terms: %s (not read by the feed: read them before accepting)", r.Terms.URL)
		}
	}
	if !r.ScopePublished {
		line("The program publishes no structured scope: the targets listed are suggestions.")
	}
	text := b.String()
	if len(text) > bp.MaxTermsText {
		text = text[:bp.MaxTermsText]
	}
	return headers, text
}

// ParseChange reads one change record.
func (V1) ParseChange(line []byte) (bp.FeedChange, error) {
	var c v1Change
	if err := feedsign.DecodeStrict(line, &c); err != nil {
		return bp.FeedChange{}, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	if !v1ChangeKinds[c.Kind] || c.Sequence == 0 || c.Program == "" || len(c.Program) > 161 {
		return bp.FeedChange{}, fmt.Errorf("%w: change %q of %q", shared.ErrValidation, c.Kind, c.Program)
	}
	return bp.FeedChange{Sequence: c.Sequence, Program: c.Program, Kind: c.Kind}, nil
}

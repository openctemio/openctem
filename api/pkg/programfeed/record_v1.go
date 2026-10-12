package programfeed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// V1 reads records of schema openctem.programfeed/v1 (the collector's
// schema/program.schema.json and schema/change.schema.json). Fields the
// schema adds later are ignored (the collector extends records within v1);
// every field read is validated, and every target is classified again by the
// platform's own parser: the feed's canonical form is not trusted to be
// scannable. Pointer and manifests stay strict (feedsign.DecodeStrict).
type V1 struct{}

type v1Target struct {
	Type              string `json:"type"`
	Value             string `json:"value"`
	Confidence        string `json:"confidence"`
	EligibleForBounty *bool  `json:"eligible_for_bounty,omitempty"`
	MaxSeverity       string `json:"max_severity,omitempty"`
	Notes             string `json:"notes,omitempty"`
	// Schema 1.1 qualifiers (all optional).
	AssetType    string   `json:"asset_type,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	PathPrefix   string   `json:"path_prefix,omitempty"`
	Environment  string   `json:"environment,omitempty"`
	Instructions string   `json:"instructions,omitempty"`
	Requires     string   `json:"requires,omitempty"`
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
// Classifier labels used more than once.
const (
	labelURL       = "url"
	labelDomain    = "domain"
	labelCIDR      = "cidr"
	labelIPAddress = "ip_address"
)

func v1Label(feedType string) string {
	switch feedType {
	case "domain", "wildcard", "cidr", "url", "mobile_app", "other":
		return feedType
	case "source_repo":
		return "source_code"
	case "ip":
		return labelIPAddress
	}
	return ""
}

func v1Item(t v1Target, inScope bool) (bp.Item, error) {
	label := v1Label(t.Type)
	if label == "" || len(t.Value) > 512 {
		return bp.Item{}, fmt.Errorf("%w: target type %q", shared.ErrValidation, t.Type)
	}
	if t.AssetType != "" {
		// The fine-grained type decides: a mobile app, a contract or a
		// model stays a program target the scanners never receive.
		if l := v1AssetLabel(t.AssetType); l != "" {
			label = l
		} else {
			label = "other"
		}
	}
	value := t.Value
	if t.PathPrefix != "" {
		value = v1PathURL(t.Value, t.PathPrefix)
	}
	it := bp.ClassifyTyped(value, label)
	it.Raw = t.Value
	if t.PathPrefix != "" {
		it.Raw = value
	}
	it.InScope, it.Confidence, it.AssetType = inScope, t.Confidence, firstNonEmpty(t.AssetType, t.Type)
	if inScope {
		// A port or protocol limit becomes the entry's constraint; one the
		// entry cannot carry leaves the target not scannable (never the
		// whole host).
		it = bp.LimitItem(it, t.Ports, t.Protocol)
	}
	it.EligibleForBounty, it.MaxSeverity, it.Environment = t.EligibleForBounty, t.MaxSeverity, t.Environment
	it.Instructions = clipText(t.Instructions, bp.MaxItemInstructions)
	it.Requires = clipText(t.Requires, bp.MaxItemRequires)
	return it, nil
}

// v1PathURL joins a URL target and its path limit ("https://x.com" and
// "/api/" give "https://x.com/api/"). A limit outside the URL's own path,
// or anything that is not a web URL, gives "" (not scannable).
func v1PathURL(value, prefix string) string {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || !strings.HasPrefix(prefix, "/") {
		return ""
	}
	base := strings.TrimSuffix(u.EscapedPath(), "/")
	if base != "" && prefix != base && !strings.HasPrefix(prefix, base+"/") {
		return ""
	}
	return u.Scheme + "://" + u.Host + prefix
}

// clipText trims s and cuts it to n bytes on a rune boundary.
func clipText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// v1AssetLabel maps the schema 1.1 asset_type onto the classifier's labels;
// "" for types that are not network targets.
func v1AssetLabel(assetType string) string {
	switch strings.ToLower(strings.TrimSpace(assetType)) {
	case "domain", "subdomain", "wildcard":
		return labelDomain
	case "ip_address", "ip":
		return labelIPAddress
	case "cidr", "ip_range":
		return labelCIDR
	case "url", "web_application", "website", "api":
		return labelURL
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Parse reads one program record.
func (V1) Parse(line []byte) (bp.PublicProgram, error) {
	var r v1Record
	if err := decodeRecord(line, &r); err != nil {
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
			OriginalPlatform: r.Provenance.OriginalPlatform, OriginalURL: r.Provenance.OriginalURL, LastChanged: r.LastChanged}}, nil
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
	if err := decodeRecord(line, &c); err != nil {
		return bp.FeedChange{}, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	if !v1ChangeKinds[c.Kind] || c.Sequence == 0 || c.Program == "" || len(c.Program) > 161 {
		return bp.FeedChange{}, fmt.Errorf("%w: change %q of %q", shared.ErrValidation, c.Kind, c.Program)
	}
	return bp.FeedChange{Sequence: c.Sequence, Program: c.Program, Kind: c.Kind}, nil
}

// decodeRecord decodes one JSON record, ignoring unknown fields and refusing
// trailing data.
func decodeRecord(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

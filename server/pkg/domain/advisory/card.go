// Package advisory holds advisory cards: reviewed, product-level statements
// from the signed vulnerability bundle (the "cards" stream of the intel side
// manifest). A card may exist before a CVE record or a CPE: it names the
// affected products by catalog key, the affected and fixed versions per
// branch (or that they are not published yet), the configuration each
// vulnerability needs (a closed list), the exploitation status, links to
// public proof-of-concept write-ups (metadata only), workarounds, detection
// ideas and the vulnerability ids it groups. Every fact cites a public
// source. An organization gets one emerging-threat alert per card, with the
// grouped vulnerabilities inside it.
//
// Cards are public facts: they hold no tenant data and are stored
// platform-wide, written only by the bundle importer.
//
// Exploitation is also the platform's one notion of public exploitation
// evidence beyond KEV and EPSS: the emerging-threat score and the urgency
// rule of version-less matching read it through Exploitation.
//
// Design: docs/rfcs/RFC-117-emerging-threat-alerts.md ("Advisory cards").
package advisory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/pkg/domain/vulnmatch"
)

// Schema is the card format this platform reads. The format grows only by
// optional fields while it stays v1, so unknown fields are ignored.
const Schema = "openctem.advisory-card/v1"

// Caps (the collector enforces the same).
const (
	MaxCards     = 2000
	MaxCardBytes = 64 << 10
	maxTitle     = 160
	maxSummary   = 600
	maxNote      = 300
	maxName      = 80
	maxURL       = 512
	maxVulns     = 64
	maxProducts  = 16
	maxAffected  = 128
	maxRanges    = 16
	maxConds     = 8
	maxLinks     = 16
	maxSources   = 32
	maxNicknames = 8
	maxHistory   = 100
)

// Versions values of an affected statement.
const (
	VersionsPublished    = "published"
	VersionsNotPublished = "not_published"
)

// Review states a published card can have.
//
// StateReported is the corroborated fast lane: a card no person has
// reviewed yet, published because every fact cites a vendor, CNA or CERT
// source. It is shown as "reported, not yet reviewed" and used for alerts
// only: its exploitation status adds no score and opens no "check needed",
// it does not group the alerts of its vulnerabilities, and it creates no
// finding and no scan.
const (
	StateReported  = "reported"
	StateReviewed  = "reviewed"
	StateWithdrawn = "withdrawn"
)

// Review modes.
const (
	ModeTwoPerson    = "two_person"
	ModeSingleReview = "single_review"
)

// Exploitation is how far exploitation of a vulnerability has gone, as a
// reviewed card states it.
type Exploitation string

// Exploitation statuses, weakest first.
const (
	ExploitNone            Exploitation = "none"
	ExploitPoCPublic       Exploitation = "poc_public"
	ExploitWeaponised      Exploitation = "weaponised"
	ExploitInTheWild       Exploitation = "exploited_itw"
	ExploitVendorConfirmed Exploitation = "vendor_confirmed_exploited"
)

var exploitations = []Exploitation{ExploitNone, ExploitPoCPublic, ExploitWeaponised, ExploitInTheWild, ExploitVendorConfirmed}

// Rank orders statuses: 0 for none or unknown, 4 for vendor-confirmed.
func (e Exploitation) Rank() int { return max(0, slices.Index(exploitations, e)) }

// IsValid reports whether e is a known status.
func (e Exploitation) IsValid() bool { return slices.Contains(exploitations, e) }

// PublicExploit reports whether working exploitation is public: a public
// proof of concept or anything stronger.
func (e Exploitation) PublicExploit() bool { return e.Rank() >= ExploitPoCPublic.Rank() }

// Stronger returns the stronger of two statuses.
func Stronger(a, b Exploitation) Exploitation {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// Predicates is the closed list of configuration conditions. A predicate
// this platform does not know reads as "other" (it cannot narrow).
func Predicates() []string {
	return []string{"http2_enabled", "http3_enabled", "mail_proxy_auth_http", "resolver_runtime_dns", "kernel_sctp_reachable", "other"}
}

var (
	idRe       = regexp.MustCompile(`^OCA-[0-9]{4}-[0-9]{4,6}$`)
	cveRe      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	ghsaRe     = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	keyRe      = regexp.MustCompile(`^([aoh]):([a-z0-9][a-z0-9._\-]{0,63}):([a-z0-9][a-z0-9._\-+]{0,95})$`)
	versionRe  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~:_\-]{0,63}$`)
	sourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,47}$`)
	handleRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-]{0,39}$`)
)

// IsCardID reports whether s is a card id (OCA-YYYY-NNNN). Card ids and CVE
// ids never collide, so an alert's key tells which one it is.
func IsCardID(s string) bool { return idRe.MatchString(s) }

// Source is one public document a card cites.
type Source struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Publisher   string    `json:"publisher"`
	Tier        string    `json:"tier"`
	Title       string    `json:"title"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

// Vuln is one vulnerability id the card groups.
type Vuln struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Sources []string `json:"sources"`
}

// Product is one product by catalog key (part:vendor:product).
type Product struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// Range is one affected range of upstream versions.
type Range struct {
	Branch       string `json:"branch,omitempty"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Condition is a configuration a vulnerability needs.
type Condition struct {
	Predicate string `json:"predicate"`
	Note      string `json:"note,omitempty"`
}

// Affected states which versions of a product some vulnerabilities affect.
type Affected struct {
	Product    string      `json:"product"`
	Vulns      []string    `json:"vulns"`
	Versions   string      `json:"versions"`
	Ranges     []Range     `json:"ranges,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
	Sources    []string    `json:"sources"`
}

// Fact is a short cited statement.
type Fact struct {
	Status  string   `json:"status,omitempty"`
	Level   string   `json:"level,omitempty"`
	Note    string   `json:"note,omitempty"`
	Sources []string `json:"sources"`
}

// Link is metadata of a public proof of concept or write-up.
type Link struct {
	URL       string   `json:"url"`
	Kind      string   `json:"kind"`
	Title     string   `json:"title"`
	FirstSeen string   `json:"first_seen,omitempty"`
	Sources   []string `json:"sources"`
}

// Workaround is a mitigation and what it blocks.
type Workaround struct {
	Text    string   `json:"text"`
	Blocks  []string `json:"blocks"`
	Caveat  string   `json:"caveat,omitempty"`
	Sources []string `json:"sources"`
}

// Detection is an idea for finding affected or attacked systems.
type Detection struct {
	Kind    string   `json:"kind"`
	Text    string   `json:"text"`
	Sources []string `json:"sources"`
}

// Review is the card's review record.
type Review struct {
	State           string     `json:"state"`
	Author          string     `json:"author"`
	ReviewedBy      string     `json:"reviewed_by,omitempty"`
	ReviewedAt      *time.Time `json:"reviewed_at,omitempty"`
	Mode            string     `json:"mode,omitempty"`
	WithdrawnReason string     `json:"withdrawn_reason,omitempty"`
}

// Change is one revision in the card's history.
type Change struct {
	Revision int       `json:"revision"`
	At       time.Time `json:"at"`
	Note     string    `json:"note"`
}

// Card is one advisory card.
type Card struct {
	Schema       string       `json:"schema"`
	ID           string       `json:"id"`
	Revision     int          `json:"revision"`
	Title        string       `json:"title"`
	Nicknames    []string     `json:"nicknames,omitempty"`
	Summary      string       `json:"summary"`
	PublishedAt  time.Time    `json:"published_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	Severity     Fact         `json:"severity"`
	Vulns        []Vuln       `json:"vulns"`
	Products     []Product    `json:"products"`
	Affected     []Affected   `json:"affected"`
	Exploitation Fact         `json:"exploitation"`
	PoC          []Link       `json:"poc,omitempty"`
	Workarounds  []Workaround `json:"workarounds,omitempty"`
	Detection    []Detection  `json:"detection,omitempty"`
	Sources      []Source     `json:"sources"`
	Review       Review       `json:"review"`
	History      []Change     `json:"history"`
}

// Withdrawn reports whether the card no longer stands.
func (c *Card) Withdrawn() bool { return c.Review.State == StateWithdrawn }

// Reported reports whether the card is in the fast lane (not yet reviewed
// by a person).
func (c *Card) Reported() bool { return c.Review.State == StateReported }

// ExploitationStatus is the card's exploitation as a typed value.
func (c *Card) ExploitationStatus() Exploitation { return Exploitation(c.Exploitation.Status) }

// VulnIDs lists the grouped vulnerability ids.
func (c *Card) VulnIDs() []string {
	out := make([]string, 0, len(c.Vulns))
	for _, v := range c.Vulns {
		out = append(out, v.ID)
	}
	return out
}

// ProductKey is a product key split into its catalog parts.
type ProductKey struct{ Part, Vendor, Product string }

// ProductKeys lists the card's products.
func (c *Card) ProductKeys() []ProductKey {
	out := make([]ProductKey, 0, len(c.Products))
	for _, p := range c.Products {
		if m := keyRe.FindStringSubmatch(p.Key); m != nil {
			out = append(out, ProductKey{Part: m[1], Vendor: m[2], Product: m[3]})
		}
	}
	return out
}

// VersionMatch says how a product version relates to the card.
type VersionMatch int

// Version matches.
const (
	// VersionNotAffected: every statement for the product has published
	// ranges and the version is outside all of them.
	VersionNotAffected VersionMatch = iota
	// VersionUnknown: the version is unknown, does not parse, or a
	// statement says the versions are not published yet.
	VersionUnknown
	// VersionAffected: the version is inside a published range.
	VersionAffected
)

// MatchVersion places version (upstream, generic scheme) against the card's
// statements for the product key (part:vendor:product).
func (c *Card) MatchVersion(productKey, version string) VersionMatch {
	result := VersionNotAffected
	seen := false
	for _, a := range c.Affected {
		if a.Product != productKey {
			continue
		}
		seen = true
		if a.Versions != VersionsPublished || version == "" {
			result = VersionUnknown
			continue
		}
		for _, r := range a.Ranges {
			switch inRange(r, version) {
			case VersionAffected:
				return VersionAffected
			case VersionUnknown:
				result = VersionUnknown
			}
		}
	}
	if !seen {
		return VersionNotAffected
	}
	return result
}

func inRange(r Range, v string) VersionMatch {
	cmp := func(bound string) (int, bool) { return vulnmatch.CompareVersions(vulnmatch.SchemeGeneric, v, bound) }
	if r.Introduced != "" {
		c, ok := cmp(r.Introduced)
		if !ok {
			return VersionUnknown
		}
		if c < 0 {
			return VersionNotAffected
		}
	}
	switch {
	case r.Fixed != "":
		c, ok := cmp(r.Fixed)
		if !ok {
			return VersionUnknown
		}
		if c >= 0 {
			return VersionNotAffected
		}
	case r.LastAffected != "":
		c, ok := cmp(r.LastAffected)
		if !ok {
			return VersionUnknown
		}
		if c > 0 {
			return VersionNotAffected
		}
	}
	return VersionAffected
}

// Conditions lists the distinct predicates the card's statements need.
func (c *Card) Conditions() []string {
	var out []string
	for _, a := range c.Affected {
		for _, cd := range a.Conditions {
			if !slices.Contains(out, cd.Predicate) {
				out = append(out, cd.Predicate)
			}
		}
	}
	return out
}

// Decode reads one card from the bundle (unknown fields ignored, size
// capped) and validates it.
func Decode(raw []byte) (*Card, error) {
	if len(raw) > MaxCardBytes {
		return nil, fmt.Errorf("card: %d bytes, over %d", len(raw), MaxCardBytes)
	}
	var c Card
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("card: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks a published card: the shape, the caps, display text,
// citations and the review record. The collector checked the same before
// signing; the platform checks again because the card is shown to people.
//
//nolint:gocyclo,cyclop,gocognit // one flat check per rule, kept in one place on purpose
func (c *Card) Validate() error {
	fail := func(format string, a ...any) error {
		id := c.ID
		if !idRe.MatchString(id) {
			id = "?"
		}
		return fmt.Errorf("card %s: %s", id, fmt.Sprintf(format, a...))
	}
	switch {
	case c.Schema != Schema:
		return fail("schema is not %s", Schema)
	case !idRe.MatchString(c.ID):
		return fail("malformed id")
	case c.Revision < 1:
		return fail("revision")
	case c.PublishedAt.IsZero() || c.UpdatedAt.IsZero() || c.UpdatedAt.Before(c.PublishedAt):
		return fail("dates")
	case len(c.Nicknames) > maxNicknames || len(c.Sources) == 0 || len(c.Sources) > maxSources ||
		len(c.Vulns) == 0 || len(c.Vulns) > maxVulns || len(c.Products) == 0 || len(c.Products) > maxProducts ||
		len(c.Affected) == 0 || len(c.Affected) > maxAffected || len(c.PoC) > maxLinks ||
		len(c.Workarounds) > maxLinks || len(c.Detection) > maxLinks || len(c.History) > maxHistory:
		return fail("a list is empty or over its cap")
	}
	texts := []struct {
		v   string
		max int
		req bool
	}{{c.Title, maxTitle, true}, {c.Summary, maxSummary, true}, {c.Severity.Note, maxNote, false}, {c.Exploitation.Note, maxNote, false}}
	for _, n := range c.Nicknames {
		texts = append(texts, struct {
			v   string
			max int
			req bool
		}{n, 40, true})
	}
	for _, t := range texts {
		if err := Text(t.v, t.max, t.req); err != nil {
			return fail("%v", err)
		}
	}
	src := map[string]string{} // id -> tier
	for _, s := range c.Sources {
		if !sourceIDRe.MatchString(s.ID) || src[s.ID] != "" || !slices.Contains([]string{"vendor", "cna", "cert", "researcher", "press"}, s.Tier) {
			return fail("source %q", s.ID)
		}
		src[s.ID] = s.Tier
		if err := errors.Join(HTTPSURL(s.URL), Text(s.Publisher, maxName, true), Text(s.Title, maxTitle, true)); err != nil {
			return fail("source %s: %v", s.ID, err)
		}
	}
	// A reported card stands only on first-hand sources: every fact cites
	// a vendor, CNA or CERT document.
	reported := c.Reported()
	cited := func(ids []string) bool {
		if len(ids) == 0 {
			return false
		}
		firstHand := false
		for _, id := range ids {
			switch src[id] {
			case "":
				return false
			case "vendor", "cna", "cert":
				firstHand = true
			}
		}
		return firstHand || !reported
	}
	if !slices.Contains([]string{"critical", "high", "medium", "low"}, c.Severity.Level) || !cited(c.Severity.Sources) {
		return fail("severity")
	}
	if !Exploitation(c.Exploitation.Status).IsValid() || !cited(c.Exploitation.Sources) {
		return fail("exploitation")
	}
	vulns := map[string]bool{}
	for _, v := range c.Vulns {
		if len(v.ID) > 32 || (!cveRe.MatchString(v.ID) && !ghsaRe.MatchString(v.ID)) || vulns[v.ID] || !cited(v.Sources) {
			return fail("vulnerability %q", v.ID)
		}
		vulns[v.ID] = true
		if err := Text(v.Title, maxTitle, true); err != nil {
			return fail("%s: %v", v.ID, err)
		}
	}
	known := func(ids []string) bool {
		if len(ids) == 0 {
			return false
		}
		for _, id := range ids {
			if !vulns[id] {
				return false
			}
		}
		return true
	}
	products := map[string]bool{}
	for _, p := range c.Products {
		if !keyRe.MatchString(p.Key) || products[p.Key] {
			return fail("product %q", p.Key)
		}
		products[p.Key] = true
		if err := Text(p.Name, maxName, true); err != nil {
			return fail("product %s: %v", p.Key, err)
		}
	}
	for i, a := range c.Affected {
		if !products[a.Product] || !known(a.Vulns) || !cited(a.Sources) || len(a.Ranges) > maxRanges || len(a.Conditions) > maxConds {
			return fail("affected[%d]", i)
		}
		if (a.Versions == VersionsPublished) == (len(a.Ranges) == 0) || (a.Versions != VersionsPublished && a.Versions != VersionsNotPublished) {
			return fail("affected[%d]: versions", i)
		}
		for _, r := range a.Ranges {
			for _, v := range []string{r.Introduced, r.Fixed, r.LastAffected} {
				if v != "" && !versionRe.MatchString(v) {
					return fail("affected[%d]: version", i)
				}
			}
			if (r.Fixed != "" && r.LastAffected != "") || (r.Introduced == "" && r.Fixed == "" && r.LastAffected == "") {
				return fail("affected[%d]: range", i)
			}
			if err := Text(r.Branch, 40, false); err != nil {
				return fail("affected[%d]: %v", i, err)
			}
		}
		for j, cd := range a.Conditions {
			if !slices.Contains(Predicates(), cd.Predicate) {
				c.Affected[i].Conditions[j].Predicate = "other"
			}
			if err := Text(cd.Note, maxNote, false); err != nil {
				return fail("affected[%d]: %v", i, err)
			}
		}
	}
	for i, l := range c.PoC {
		if !slices.Contains([]string{"write_up", "exploit_code", "scanner_template"}, l.Kind) || !cited(l.Sources) {
			return fail("poc[%d]", i)
		}
		if err := errors.Join(HTTPSURL(l.URL), Text(l.Title, maxTitle, true)); err != nil {
			return fail("poc[%d]: %v", i, err)
		}
		if l.FirstSeen != "" {
			if _, err := time.Parse("2006-01-02", l.FirstSeen); err != nil {
				return fail("poc[%d]: first_seen", i)
			}
		}
	}
	for i, w := range c.Workarounds {
		if !known(w.Blocks) || !cited(w.Sources) {
			return fail("workarounds[%d]", i)
		}
		if err := errors.Join(Text(w.Text, maxNote, true), Text(w.Caveat, maxNote, false)); err != nil {
			return fail("workarounds[%d]: %v", i, err)
		}
	}
	for i, d := range c.Detection {
		if !slices.Contains([]string{"safe_check", "version_check", "config_check", "log_hint", "host_hint"}, d.Kind) || !cited(d.Sources) {
			return fail("detection[%d]", i)
		}
		if err := Text(d.Text, maxNote, true); err != nil {
			return fail("detection[%d]: %v", i, err)
		}
	}
	for i, h := range c.History {
		if err := Text(h.Note, maxNote, true); err != nil {
			return fail("history[%d]: %v", i, err)
		}
	}
	return c.validateReview(fail)
}

func (c *Card) validateReview(fail func(string, ...any) error) error {
	r := c.Review
	if r.State == StateReported {
		if !handleRe.MatchString(r.Author) || r.ReviewedBy != "" || r.ReviewedAt != nil || r.Mode != "" || r.WithdrawnReason != "" {
			return fail("a reported card has an author and no reviewer yet")
		}
		return nil
	}
	switch {
	case r.State != StateReviewed && r.State != StateWithdrawn:
		return fail("only reported, reviewed or withdrawn cards are published")
	case !handleRe.MatchString(r.Author) || !handleRe.MatchString(r.ReviewedBy) || r.ReviewedAt == nil:
		return fail("review record")
	case r.Mode == ModeTwoPerson && strings.EqualFold(r.Author, r.ReviewedBy):
		return fail("two_person review by its author")
	case r.Mode == ModeSingleReview && !strings.EqualFold(r.Author, r.ReviewedBy):
		return fail("single_review by another person")
	case r.Mode != ModeTwoPerson && r.Mode != ModeSingleReview:
		return fail("review mode")
	case r.State == StateWithdrawn && r.WithdrawnReason == "":
		return fail("withdrawn without a reason")
	}
	return Text(r.WithdrawnReason, maxNote, false)
}

// Text checks display text from a card: valid UTF-8 within its cap, no
// control, bidirectional-override, zero-width, line or paragraph separator
// characters, no markup brackets and no link (a scheme or a www. host).
// Card text is shown to people as plain text and reaches chat titles; it
// must not be able to restyle, reorder or hide anything, and links come only
// from the vetted url fields.
func Text(s string, maxLen int, required bool) error {
	if err := plainText(s, maxLen, required); err != nil {
		return err
	}
	if l := strings.ToLower(s); strings.Contains(l, "://") || strings.Contains(l, "www.") {
		return errors.New("a text holds a link; links belong in url fields")
	}
	return nil
}

func plainText(s string, maxLen int, required bool) error {
	if s == "" {
		if required {
			return errors.New("a required text is empty")
		}
		return nil
	}
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxLen {
		return fmt.Errorf("a text is over %d characters or not UTF-8", maxLen)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || r == '<' || r == '>' {
			return fmt.Errorf("a text holds a forbidden character (U+%04X)", r)
		}
	}
	return nil
}

// HTTPSURL checks a link: absolute https without credentials.
func HTTPSURL(raw string) error {
	if len(raw) > maxURL {
		return errors.New("a link is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return errors.New("a link is not an absolute https URL without credentials")
	}
	return plainText(raw, maxURL, true)
}

// Applied says what one import of the cards stream changed.
type Applied struct {
	Published int
	Updated   int
	Withdrawn int
	Unchanged int
}

// Supersedes reports whether an incoming card replaces the stored revision
// heldRevision in state heldState: a higher revision always does; at the
// same revision only a withdrawal of a card that still stands does. A
// withdrawn card comes back only with a higher revision, so a replayed or
// unchecked stream can never undo a withdrawal. A reported card (no
// person's review) never replaces a reviewed or withdrawn one: reported is
// only a first publication or a successor of a reported card.
func Supersedes(heldRevision int, heldState string, c *Card) bool {
	switch {
	case c.Revision > heldRevision:
		return !c.Reported() || (heldState != StateReviewed && heldState != StateWithdrawn)
	case c.Revision == heldRevision:
		return heldState != StateWithdrawn && c.Withdrawn()
	}
	return false
}

// StreamApplied identifies one cards stream the platform applied.
type StreamApplied struct {
	Sequence uint64
	// FileSHA256 is the SHA-256 of the cards file from the verified
	// manifest: the stream is applied whenever it differs from the last one
	// applied (never by data date: a card reviewed earlier but merged later,
	// or a withdrawal without a later timestamp, keeps the date).
	FileSHA256 string
	// AsOf is the stream's data date, kept for the freshness status only.
	AsOf time.Time
}

// Store keeps the cards (platform-wide, public facts).
type Store interface {
	// AppliedFile is the SHA-256 of the last cards file applied (empty
	// when none).
	AppliedFile(ctx context.Context) (string, error)
	// Apply writes the cards and records the stream in one transaction: a
	// card that Supersedes the stored one replaces it, every revision body
	// is kept, and a card event (published, updated or withdrawn, keyed by
	// the card id) is logged for the alert planner. A card the stream no
	// longer holds is kept as it is.
	Apply(ctx context.Context, cards []*Card, stream StreamApplied, now time.Time) (Applied, error)
	// ExploitationFor maps each vulnerability id to the strongest
	// exploitation a stored card states for it (ids without a card are
	// absent). Withdrawn cards state nothing.
	ExploitationFor(ctx context.Context, vulnIDs []string) (map[string]Exploitation, error)
}

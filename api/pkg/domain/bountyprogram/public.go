package bountyprogram

// Public programs (RFC-065 §16): the platform catalog of public bug-bounty
// and disclosure programs, imported from the signed program feed. Global (no
// tenant): a public program's published scope is public data. A feed target
// is never permission to test: an organization follows a program and gets
// its own program, whose entries stay inactive until a member accepts the
// terms; targets the feed only inferred are suggestions a member confirms
// first.

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope source and status of a followed program.
const (
	// ScopeSourcePublicFeed: the scope comes from the program feed.
	ScopeSourcePublicFeed = "public_feed"
	// StatusPendingAttestation: entries exist but are inactive until a
	// member accepts the program's current terms (followed programs).
	StatusPendingAttestation Status = "pending_attestation"
)

// Feed target confidence. Only published (the program's own scope) makes
// entries without a confirmation; published_by_platform (scope a hosting
// platform published, read through a public dataset) and inferred are
// suggestions a follower confirms first.
const (
	ConfidencePublished           = "published"
	ConfidencePublishedByPlatform = "published_by_platform"
	ConfidenceInferred            = "inferred"
)

// FeedProvenance says where a feed record comes from; dataset fields are
// set when it was read through a public aggregate dataset.
type FeedProvenance struct {
	Source           string    `json:"source"`
	SourceURL        string    `json:"source_url"`
	FetchedAt        time.Time `json:"fetched_at"`
	Dataset          string    `json:"dataset,omitempty"`
	DatasetCommit    string    `json:"dataset_commit,omitempty"`
	OriginalPlatform string    `json:"original_platform,omitempty"`
	OriginalURL      string    `json:"original_url,omitempty"`
}

// Feed program status.
const (
	FeedStatusOpen   = "open"
	FeedStatusPaused = "paused"
	FeedStatusClosed = "closed"
)

// Feed change kinds the platform acts on.
const (
	FeedChangeDropped = "program_dropped"
)

// Bounds of a feed record.
const (
	MaxFeedURLLength      = 2048
	MaxFeedPlatformLength = 64
	MaxFeedItems          = 2 * MaxScopeItems
)

var feedIDRE = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,31}):([a-z0-9][a-z0-9._-]{0,127})$`)

// PublicProgram is one program of the catalog.
type PublicProgram struct {
	ID shared.ID
	// FeedID is "<source>:<slug>", stable across feed runs.
	FeedID   string
	Source   string
	Platform string
	// Handle is the slug part of FeedID.
	Handle         string
	Name           string
	URL            string
	Type           string // bounty, vdp
	Status         string // open, paused, closed
	OffersBounty   bool
	ScopePublished bool
	// Items are the in-scope and out-of-scope targets, each with the feed's
	// confidence (published or inferred).
	Items []Item
	// Rules are what the platform enforces from the feed's rules (required
	// headers); the rest is in TermsText.
	Rules Rules
	// TermsText is what a person reads before accepting: the feed's rules
	// summary and restrictions, and the terms document with its hash.
	TermsText      string
	TermsURL       string
	TermsDocSHA256 string
	// TermsSHA256 identifies the catalog content (change detection).
	TermsSHA256 string
	AsOf        time.Time
	Provenance  FeedProvenance
	// LocalOnly: the record came from the operator's local bundle (owner
	// option A), not the signed feed; every in-scope target is a suggestion.
	LocalOnly bool
	RemovedAt *time.Time
	Sequence  uint64
	UpdatedAt time.Time
}

// Open reports whether the program takes submissions.
func (p *PublicProgram) Open() bool { return p.Status == FeedStatusOpen }

// FeedChange is one entry of a bundle's change log.
type FeedChange struct {
	Sequence uint64
	Program  string
	Kind     string
}

// Catalog errors.
var (
	ErrPublicProgramGone = shared.NewDomainError("PUBLIC_PROGRAM_GONE", "the program is no longer published or takes no submissions", shared.ErrConflict)
	ErrAlreadySubscribed = shared.NewDomainError("PROGRAM_ALREADY_SUBSCRIBED", "the organization already follows this program", shared.ErrConflict)
	ErrNotInferred       = shared.NewDomainError("PROGRAM_TARGET_NOT_SUGGESTED", "only targets the feed suggests for this program can be confirmed", shared.ErrValidation)
)

// Validate checks a feed record after parsing and computes its content
// hash; a bundle with one invalid record is refused whole.
//
//nolint:cyclop // one check per field
func (p *PublicProgram) Validate() error {
	m := feedIDRE.FindStringSubmatch(p.FeedID)
	switch {
	case m == nil:
		return fmt.Errorf("%w: id %q is not <source>:<slug>", shared.ErrValidation, clip(p.FeedID))
	case m[1] != p.Source:
		return fmt.Errorf("%w: %s: source %q is not the id prefix", shared.ErrValidation, p.FeedID, clip(p.Source))
	case strings.TrimSpace(p.Name) == "" || len(p.Name) > MaxNameLength || hasControl(p.Name):
		return fmt.Errorf("%w: %s: name", shared.ErrValidation, p.FeedID)
	case len(p.Platform) > MaxFeedPlatformLength || hasControl(p.Platform):
		return fmt.Errorf("%w: %s: platform", shared.ErrValidation, p.FeedID)
	case p.Type != "bounty" && p.Type != "vdp":
		return fmt.Errorf("%w: %s: type", shared.ErrValidation, p.FeedID)
	case p.Status != FeedStatusOpen && p.Status != FeedStatusPaused && p.Status != FeedStatusClosed:
		return fmt.Errorf("%w: %s: status", shared.ErrValidation, p.FeedID)
	case p.AsOf.IsZero():
		return fmt.Errorf("%w: %s: last_seen", shared.ErrValidation, p.FeedID)
	case len(p.Items) > MaxFeedItems:
		return fmt.Errorf("%s: %w", p.FeedID, ErrScopeTooLarge)
	case p.TermsDocSHA256 != "" && !hexSHA256RE.MatchString(p.TermsDocSHA256):
		return fmt.Errorf("%w: %s: terms sha256", shared.ErrValidation, p.FeedID)
	}
	p.Handle = m[2]
	for _, u := range []string{p.URL, p.TermsURL} {
		if !webURL(u) {
			return fmt.Errorf("%w: %s: url %q", shared.ErrValidation, p.FeedID, clip(u))
		}
	}
	p.Rules = p.Rules.Normalize()
	if err := p.Rules.Validate(); err != nil {
		return fmt.Errorf("%s: %w", p.FeedID, err)
	}
	p.TermsText = strings.TrimSpace(p.TermsText)
	if err := ValidateTermsText(p.TermsText); err != nil {
		return fmt.Errorf("%s: %w", p.FeedID, err)
	}
	for _, it := range p.Items {
		switch it.Confidence {
		case ConfidencePublished, ConfidencePublishedByPlatform, ConfidenceInferred:
		default:
			return fmt.Errorf("%w: %s: target confidence", shared.ErrValidation, p.FeedID)
		}
	}
	if err := p.Provenance.validate(); err != nil {
		return fmt.Errorf("%s: %w", p.FeedID, err)
	}
	p.Items = dedupe(append([]Item(nil), p.Items...))
	p.TermsSHA256 = NewTerms(p.URL, p.Rules, p.Items).WithText(p.TermsText + "\n" + p.Status + "\n" + inferredKeys(p.Items)).SHA256()
	return nil
}

var (
	hexSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	datasetRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)
	commitRE    = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func (v FeedProvenance) validate() error {
	switch {
	case v.Source == "" || len(v.Source) > 64 || hasControl(v.Source):
		return fmt.Errorf("%w: provenance source", shared.ErrValidation)
	case !webURL(v.SourceURL) || v.SourceURL == "":
		return fmt.Errorf("%w: provenance source_url", shared.ErrValidation)
	case v.Dataset != "" && !datasetRE.MatchString(v.Dataset):
		return fmt.Errorf("%w: provenance dataset", shared.ErrValidation)
	case v.DatasetCommit != "" && !commitRE.MatchString(v.DatasetCommit):
		return fmt.Errorf("%w: provenance dataset_commit", shared.ErrValidation)
	case len(v.OriginalPlatform) > MaxFeedPlatformLength || hasControl(v.OriginalPlatform):
		return fmt.Errorf("%w: provenance original_platform", shared.ErrValidation)
	case !webURL(v.OriginalURL):
		return fmt.Errorf("%w: provenance original_url", shared.ErrValidation)
	}
	return nil
}

// webURL accepts "" or an http(s) URL without credentials or fragment.
func webURL(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > MaxFeedURLLength || hasControl(s) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.Fragment == ""
}

func inferredKeys(items []Item) string {
	var b strings.Builder
	for _, it := range items {
		if it.Confidence != ConfidencePublished {
			b.WriteString(it.Confidence + ":" + it.Raw)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// ProgramURL is the link a followed program keeps: https only.
func (p *PublicProgram) ProgramURL() string {
	if strings.HasPrefix(p.URL, "https://") && len(p.URL) <= MaxURLLength {
		return p.URL
	}
	return ""
}

// ItemsFor are a followed program's items: published targets as the feed
// has them, inferred in-scope targets only once a member confirmed them
// (until then they are suggestions no entry is made from).
func (p *PublicProgram) ItemsFor(confirmed []string) []Item {
	ok := make(map[string]bool, len(confirmed))
	for _, c := range confirmed {
		ok[strings.ToLower(c)] = true
	}
	out := make([]Item, 0, len(p.Items))
	for _, it := range p.Items {
		if it.InScope && (it.Confidence != ConfidencePublished || p.LocalOnly) && !ok[strings.ToLower(it.Raw)] {
			it.Kind, it.TargetType, it.Pattern = KindOther, "", ""
			it.Note = "suggested (" + it.Confidence + "): confirm it before it can be scanned"
		}
		out = append(out, it)
	}
	return out
}

// IsSuggestion reports whether raw is an inferred in-scope target of p.
func (p *PublicProgram) IsSuggestion(raw string) bool {
	for _, it := range p.Items {
		if it.InScope && (it.Confidence != ConfidencePublished || p.LocalOnly) && strings.EqualFold(it.Raw, raw) {
			return true
		}
	}
	return false
}

// CatalogChange is what one feed run changed for one program.
type CatalogChange struct {
	ProgramID shared.ID
	FeedID    string
	// Kind: added, changed (content), removed (archived).
	Kind string
}

// Catalog change kinds.
const (
	ChangeAdded   = "added"
	ChangeChanged = "changed"
	ChangeRemoved = "removed"
)

// FeedState is what the platform last applied.
type FeedState struct {
	AppliedSequence uint64
	KeySetVersion   uint64
	AppliedAt       *time.Time
}

// Feed streams: the signed feed and the operator's local bundle.
const (
	StreamSigned = "signed"
	StreamLocal  = "local"
)

// FeedApply is one verified bundle to apply.
type FeedApply struct {
	// Stream is signed or local: each has its own applied sequence and
	// archives only its own programs; a signed record wins over a local
	// one with the same id.
	Stream string
	State  FeedState
	// Snapshot: Programs is the whole catalog (programs missing are
	// archived). Otherwise a delta: Programs are upserted and Dropped
	// archived.
	Snapshot bool
	Programs []PublicProgram
	Dropped  []string
}

// CatalogRepository stores the catalog and finds stale subscriptions.
type CatalogRepository interface {
	// FeedState returns the applied sequence and key-set version of a
	// stream.
	FeedState(ctx context.Context, stream string) (FeedState, error)
	// Apply writes a verified bundle in one transaction and records the
	// state (refusing a sequence not newer than the applied one).
	Apply(ctx context.Context, a FeedApply) ([]CatalogChange, error)
	// ListPublic lists published (not archived) programs matching search.
	ListPublic(ctx context.Context, search string, limit, offset int) ([]PublicProgram, int, error)
	// GetPublic returns one catalog program.
	GetPublic(ctx context.Context, id shared.ID) (*PublicProgram, error)
	// StaleSubscriptions lists followed programs (any tenant) whose catalog
	// program changed since they were brought up to date.
	StaleSubscriptions(ctx context.Context, limit int) ([]ProgramRef, error)
}

// LocalBundleSetting is the platform administrator's switch for the local
// bundle source (off by default).
type LocalBundleSetting struct {
	Enabled   bool
	Reason    string
	ChangedBy string
	ChangedAt *time.Time
}

// FeedSourceSettings stores the local bundle switch.
type FeedSourceSettings interface {
	LocalBundle(ctx context.Context) (LocalBundleSetting, error)
	SetLocalBundle(ctx context.Context, s LocalBundleSetting) error
}

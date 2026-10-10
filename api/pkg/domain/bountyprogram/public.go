package bountyprogram

// Public programs (RFC-065 §16): the platform catalog of public bug-bounty
// programs, imported from the signed program feed. Global (no tenant): a
// public program's published scope is public data. An organization
// subscribes to one and gets its own program, whose entries stay inactive
// until a member accepts the terms.

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope source and status of a subscribed program.
const (
	// ScopeSourcePublicFeed: the scope comes from the program feed.
	ScopeSourcePublicFeed = "public_feed"
	// StatusPendingAttestation: entries exist but are inactive until a
	// member accepts the program's current terms (subscribed programs).
	StatusPendingAttestation Status = "pending_attestation"
)

// Bounds of a feed record.
const (
	MaxFeedIDLength = 160
	MaxSourceLength = 100
)

var feedIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}:[A-Za-z0-9_.-]{1,100}$`)

// PublicProgram is one program of the catalog.
type PublicProgram struct {
	ID shared.ID
	// FeedID is "<platform>:<handle>", stable across feed runs.
	FeedID       string
	Platform     string
	Handle       string
	Name         string
	URL          string
	OffersBounty bool
	// Open is false when the program no longer takes submissions.
	Open      bool
	Items     []Item
	Rules     Rules
	TermsText string
	// TermsSHA256 is the hash of the program's terms (NewTerms).
	TermsSHA256 string
	// Source and AsOf name where the collector read the program and when.
	Source    string
	AsOf      time.Time
	RemovedAt *time.Time
	Sequence  uint64
	UpdatedAt time.Time
}

// ErrPublicProgramGone: the catalog no longer lists the program.
var ErrPublicProgramGone = shared.NewDomainError("PUBLIC_PROGRAM_GONE", "the program is no longer published", shared.ErrConflict)

// ErrAlreadySubscribed: the organization already follows this program.
var ErrAlreadySubscribed = shared.NewDomainError("PROGRAM_ALREADY_SUBSCRIBED", "the organization already follows this program", shared.ErrConflict)

// Validate checks a feed record after parsing and computes its hash; a
// feed with one invalid record is refused whole.
func (p *PublicProgram) Validate() error {
	switch {
	case !feedIDRE.MatchString(p.FeedID):
		return fmt.Errorf("%w: id %q is not <platform>:<handle>", shared.ErrValidation, clip(p.FeedID))
	case p.Platform+":"+p.Handle != p.FeedID:
		return fmt.Errorf("%w: id %s does not match platform and handle", shared.ErrValidation, p.FeedID)
	case len(p.Source) == 0 || len(p.Source) > MaxSourceLength || hasControl(p.Source):
		return fmt.Errorf("%w: %s: source", shared.ErrValidation, p.FeedID)
	case p.AsOf.IsZero():
		return fmt.Errorf("%w: %s: as_of", shared.ErrValidation, p.FeedID)
	}
	if err := ValidateDetails(p.Name, clipTo(p.Platform, MaxPlatformLength+1), clipTo(p.Handle, MaxHandleLength+1), p.URL); err != nil {
		return fmt.Errorf("%s: %w", p.FeedID, err)
	}
	if p.URL != "" {
		if u, err := url.Parse(p.URL); err != nil || u.Fragment != "" {
			return fmt.Errorf("%w: %s: url", shared.ErrValidation, p.FeedID)
		}
	}
	p.Rules = p.Rules.Normalize()
	if err := p.Rules.Validate(); err != nil {
		return fmt.Errorf("%s: %w", p.FeedID, err)
	}
	if err := ValidateTermsText(p.TermsText); err != nil {
		return fmt.Errorf("%s: %w", p.FeedID, err)
	}
	items, err := NormalizeItems(p.Items)
	if err != nil {
		return fmt.Errorf("%s: %w", p.FeedID, err)
	}
	p.Items = items
	p.TermsText = strings.TrimSpace(p.TermsText)
	p.TermsSHA256 = NewTerms(p.URL, p.Rules, p.Items).WithText(p.TermsText).SHA256()
	return nil
}

func clipTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// CatalogChange is what one feed run changed for one program.
type CatalogChange struct {
	ProgramID shared.ID
	FeedID    string
	// Kind: added, changed (scope, rules or terms), closed, removed.
	Kind string
}

// Catalog change kinds.
const (
	ChangeAdded   = "added"
	ChangeChanged = "changed"
	ChangeClosed  = "closed"
	ChangeRemoved = "removed"
)

// FeedState is what the platform last applied.
type FeedState struct {
	AppliedSequence uint64
	KeySetVersion   uint64
	AppliedAt       *time.Time
}

// CatalogRepository stores the catalog and its subscriptions.
type CatalogRepository interface {
	// FeedState returns the applied sequence and key-set version.
	FeedState(ctx context.Context) (FeedState, error)
	// ApplySnapshot replaces the catalog with a verified snapshot in one
	// transaction (programs missing from it are marked removed) and records
	// the state; it returns what changed.
	ApplySnapshot(ctx context.Context, state FeedState, programs []PublicProgram) ([]CatalogChange, error)
	// ListPublic lists open, not removed programs matching search.
	ListPublic(ctx context.Context, search string, limit, offset int) ([]PublicProgram, int, error)
	// GetPublic returns one catalog program.
	GetPublic(ctx context.Context, id shared.ID) (*PublicProgram, error)
	// StaleSubscriptions lists subscribed programs (any tenant) that differ
	// from their catalog program: other terms, or still active while the
	// catalog program is closed or removed.
	StaleSubscriptions(ctx context.Context, limit int) ([]ProgramRef, error)
}

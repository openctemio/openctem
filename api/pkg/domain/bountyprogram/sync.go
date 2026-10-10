package bountyprogram

// Program sync (RFC-065 §14): a program keeps its scope in sync with the
// researcher scope API of the platform that runs it, or with a scope file the
// program publishes on its own registrable domain. A sync narrows at once and
// keeps any widening as pending terms until a member accepts them.

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope sources of a program.
const (
	ScopeSourceAPI  = "program_api"
	ScopeSourceFile = "program_file"
)

// Bounds of the sync settings.
const (
	MaxSyncUsername = 100
	MaxSyncToken    = 512
	MaxSyncError    = 500
	// ClosedGrace: a source that has failed since its last success this
	// long ago suspends the program.
	ClosedGrace = 7 * 24 * time.Hour
)

var syncHandleRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

// Sync is a program's sync settings and state.
type Sync struct {
	URL            string // program_file
	Handle         string // program_api: the program's handle on its platform
	Username       string // program_api: the researcher's API user
	TokenEncrypted string // program_api: encrypted API token; never returned
	LastSyncedAt   *time.Time
	LastError      string
}

// PendingTerms is a widening a sync found, waiting for a member.
type PendingTerms struct {
	TermsSHA256 string
	Items       []Item
}

// SyncSourceInput configures a program's source.
type SyncSourceInput struct {
	Source   string // paste, program_api, program_file
	URL      string
	Handle   string
	Username string
	Token    string // "" keeps the stored token
}

// Sync errors.
var (
	ErrSyncNotConfigured = shared.NewDomainError("PROGRAM_SYNC_NOT_CONFIGURED", "the program has no scope source to sync from", shared.ErrValidation)
	ErrSyncFailed        = shared.NewDomainError("PROGRAM_SYNC_FAILED", "the program scope source could not be read", shared.ErrValidation)
	ErrNoPendingTerms    = shared.NewDomainError("PROGRAM_NO_PENDING_TERMS", "the program has no new terms to accept", shared.ErrConflict)
)

// ValidateSyncSource checks a source against the program's URL: a scope file
// must be an https URL on the program's own registrable domain.
func ValidateSyncSource(in SyncSourceInput, programURL string, hasToken bool) error {
	switch in.Source {
	case ScopeSourcePaste:
		return nil
	case ScopeSourceFile:
		u, err := url.Parse(strings.TrimSpace(in.URL))
		if err != nil || u.Scheme != schemeHTTPS || u.Host == "" || u.User != nil || len(in.URL) > MaxURLLength {
			return fmt.Errorf("%w: url must be an https:// link to the program's scope file", shared.ErrValidation)
		}
		pu, err := url.Parse(programURL)
		if err != nil {
			return fmt.Errorf("%w: the program URL is not valid", shared.ErrValidation)
		}
		fileRoot, err1 := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(u.Hostname()))
		progRoot, err2 := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(pu.Hostname()))
		if err1 != nil || err2 != nil || fileRoot != progRoot {
			return fmt.Errorf("%w: the scope file must be on the program's own domain (%s)", shared.ErrValidation, progRoot)
		}
		return nil
	case ScopeSourceAPI:
		switch {
		case !syncHandleRE.MatchString(in.Handle):
			return fmt.Errorf("%w: handle is the program's handle on its platform", shared.ErrValidation)
		case strings.TrimSpace(in.Username) == "" || len(in.Username) > MaxSyncUsername || hasControl(in.Username):
			return fmt.Errorf("%w: username is your API user name", shared.ErrValidation)
		case in.Token == "" && !hasToken:
			return fmt.Errorf("%w: token is your API token", shared.ErrValidation)
		case len(in.Token) > MaxSyncToken || hasControl(in.Token):
			return fmt.Errorf("%w: the API token is not valid", shared.ErrValidation)
		}
		return nil
	}
	return fmt.Errorf("%w: scope_source must be paste, program_api or program_file", shared.ErrValidation)
}

// SyncDiff is what a fetched scope changes.
type SyncDiff struct {
	// Narrowing: applied at once.
	RemovedEntries []Planned
	AddedExclusion []Planned
	// Widening: kept as pending terms.
	AddedEntries     []Planned
	RemovedExclusion []Planned
}

// Widens reports whether the fetched scope adds anything.
func (d SyncDiff) Widens() bool { return len(d.AddedEntries) > 0 || len(d.RemovedExclusion) > 0 }

// Narrows reports whether the fetched scope removes anything.
func (d SyncDiff) Narrows() bool { return len(d.RemovedEntries) > 0 || len(d.AddedExclusion) > 0 }

func plannedKey(p Planned) string {
	return strings.ToLower(EntryKey(p.TargetType, p.Pattern, p.Constraint))
}

// DiffPlans compares the accepted plan with a fetched one.
func DiffPlans(accepted, fetched Plan) SyncDiff {
	var d SyncDiff
	in := func(list []Planned) map[string]bool {
		m := make(map[string]bool, len(list))
		for _, p := range list {
			m[plannedKey(p)] = true
		}
		return m
	}
	oldE, newE := in(accepted.Entries), in(fetched.Entries)
	oldX, newX := in(accepted.Exclusions), in(fetched.Exclusions)
	for _, p := range accepted.Entries {
		if !newE[plannedKey(p)] {
			d.RemovedEntries = append(d.RemovedEntries, p)
		}
	}
	for _, p := range fetched.Entries {
		if !oldE[plannedKey(p)] {
			d.AddedEntries = append(d.AddedEntries, p)
		}
	}
	for _, p := range fetched.Exclusions {
		if !oldX[plannedKey(p)] {
			d.AddedExclusion = append(d.AddedExclusion, p)
		}
	}
	for _, p := range accepted.Exclusions {
		if !newX[plannedKey(p)] {
			d.RemovedExclusion = append(d.RemovedExclusion, p)
		}
	}
	return d
}

// ClipSyncError bounds an error message kept on the program.
func ClipSyncError(s string) string {
	if len(s) > MaxSyncError {
		return s[:MaxSyncError]
	}
	return s
}

// schemeHTTPS is the only scheme a program URL or scope file may use.
const schemeHTTPS = "https"

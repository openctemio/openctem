// Package codescan is platform code scanning of repositories: a full scan
// (the baseline) of each repository's protected branches before CI runs are
// judged on what they change, and periodic full rescans of those branches on
// a sensor. Design: docs/rfcs/RFC-091-code-scanning-baseline.md.
package codescan

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DefaultBranchToken in ProtectedBranches stands for the repository's default
// branch, whatever it is called.
const DefaultBranchToken = "{default}"

// Capabilities a code scan runs.
const (
	CapabilitySAST    = "sast"
	CapabilitySecrets = "secrets"
	CapabilitySCA     = "sca"
	CapabilityIaC     = "iac"
)

// AllCapabilities in display order.
func AllCapabilities() []string {
	return []string{CapabilitySAST, CapabilitySecrets, CapabilitySCA, CapabilityIaC}
}

// Schedules of the periodic full rescan.
const (
	ScheduleOff     = "off"
	ScheduleDaily   = "daily"
	ScheduleWeekly  = "weekly"
	ScheduleMonthly = "monthly"
)

// Routing: where a code scan runs. Auto sends public repositories to the
// platform-hosted sensors and everything else to the tenant's own sensors.
const (
	RoutingAuto     = "auto"
	RoutingPlatform = "platform"
	RoutingTenant   = "tenant"
)

// Limits.
const (
	MaxProtectedBranches = 20
	maxPatternLength     = 255
)

// Settings are the code scanning settings of a tenant (the template a
// repository inherits, RepositoryAssetID nil) or of one repository.
type Settings struct {
	ID                shared.ID
	TenantID          shared.ID
	RepositoryAssetID *shared.ID
	ProtectedBranches []string
	Capabilities      []string
	Schedule          string
	Routing           string
	Enabled           bool
	UpdatedBy         *shared.ID
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Defaults are the built-in settings, used when a tenant has no template:
// the default branch and develop, every capability, weekly, routed
// automatically.
func Defaults(tenantID shared.ID) Settings {
	return Settings{
		TenantID:          tenantID,
		ProtectedBranches: []string{DefaultBranchToken, "develop"},
		Capabilities:      AllCapabilities(),
		Schedule:          ScheduleWeekly,
		Routing:           RoutingAuto,
		Enabled:           true,
	}
}

// Validate normalizes the settings (trimmed, de-duplicated, capabilities in
// display order) and checks them. Every error wraps shared.ErrValidation.
func (s *Settings) Validate() error {
	branches := make([]string, 0, len(s.ProtectedBranches))
	for _, b := range s.ProtectedBranches {
		b = strings.TrimSpace(b)
		if b == "" || slices.Contains(branches, b) {
			continue
		}
		if !ValidPattern(b) {
			return fmt.Errorf("%w: %q is not a branch name or pattern", shared.ErrValidation, b)
		}
		branches = append(branches, b)
	}
	if len(branches) == 0 || len(branches) > MaxProtectedBranches {
		return fmt.Errorf("%w: protected branches: 1 to %d names or patterns", shared.ErrValidation, MaxProtectedBranches)
	}
	s.ProtectedBranches = branches

	want := map[string]bool{}
	for _, c := range s.Capabilities {
		c = strings.ToLower(strings.TrimSpace(c))
		if !slices.Contains(AllCapabilities(), c) {
			return fmt.Errorf("%w: unknown capability %q", shared.ErrValidation, c)
		}
		want[c] = true
	}
	caps := []string{}
	for _, c := range AllCapabilities() {
		if want[c] {
			caps = append(caps, c)
		}
	}
	if len(caps) == 0 {
		return fmt.Errorf("%w: at least one capability", shared.ErrValidation)
	}
	s.Capabilities = caps

	switch s.Schedule {
	case ScheduleOff, ScheduleDaily, ScheduleWeekly, ScheduleMonthly:
	default:
		return fmt.Errorf("%w: schedule must be off, daily, weekly or monthly", shared.ErrValidation)
	}
	switch s.Routing {
	case RoutingAuto, RoutingPlatform, RoutingTenant:
	default:
		return fmt.Errorf("%w: routing must be auto, platform or tenant", shared.ErrValidation)
	}
	return nil
}

// ValidPattern reports whether p is DefaultBranchToken, a branch name git
// accepts, or such a name with '*' wildcards ("release/*").
func ValidPattern(p string) bool {
	if p == DefaultBranchToken {
		return true
	}
	if p == "" || len(p) > maxPatternLength || strings.HasPrefix(p, "-") || strings.HasPrefix(p, "/") ||
		strings.HasSuffix(p, "/") || strings.HasSuffix(p, ".") || strings.HasSuffix(p, ".lock") ||
		strings.Contains(p, "..") || strings.Contains(p, "//") || strings.Contains(p, "@{") {
		return false
	}
	return !strings.ContainsFunc(p, func(r rune) bool {
		return r <= ' ' || r == 0x7f || strings.ContainsRune(`~^:?[\`, r)
	})
}

// Matches reports whether branch is protected by these settings, given the
// repository's default branch.
func (s Settings) Matches(branch, defaultBranch string) bool {
	for _, p := range s.ProtectedBranches {
		if p == DefaultBranchToken {
			if defaultBranch != "" && branch == defaultBranch {
				return true
			}
			continue
		}
		if ok, err := path.Match(p, branch); err == nil && ok {
			return true
		}
	}
	return false
}

// Effective returns the settings a repository uses: its own row, else the
// tenant template, else Defaults.
func Effective(tenantID shared.ID, repository, template *Settings) (Settings, string) {
	switch {
	case repository != nil:
		return *repository, SourceRepository
	case template != nil:
		return *template, SourceTemplate
	}
	return Defaults(tenantID), SourceDefault
}

// Where effective settings come from.
const (
	SourceRepository = "repository"
	SourceTemplate   = "template"
	SourceDefault    = "default"
)

// Baseline states of a protected branch.
const (
	BaselineNone    = "none"
	BaselineQueued  = "queued"
	BaselineRunning = "running"
	BaselineDone    = "done"
	BaselineFailed  = "failed"
)

// Triggers of a full scan.
const (
	TriggerBaseline = "baseline"
	TriggerSchedule = "schedule"
	TriggerRules    = "rules"
	TriggerManual   = "manual"
	TriggerStale    = "stale"
)

// Branch is a repository branch with its code scanning state.
type Branch struct {
	ID                  shared.ID
	Name                string
	IsDefault           bool
	LastCommitSHA       string
	BaselineState       string
	BaselineCommit      string
	BaselineAt          *time.Time
	BaselineError       string
	LastFullScanAt      *time.Time
	LastFullScanTrigger string
}

// HasBaseline reports whether the branch has a completed full scan.
func (b Branch) HasBaseline() bool { return b.BaselineState == BaselineDone && b.BaselineCommit != "" }

// ErrNotFound: no such repository (or not in the caller's scope).
var ErrNotFound = fmt.Errorf("%w: repository not found", shared.ErrNotFound)

// ErrNoProtectedBranch: re-baseline was asked for a repository none of
// whose known branches is protected.
var ErrNoProtectedBranch = fmt.Errorf("%w: no known branch of the repository is protected", shared.ErrConflict)

// RepositoryRef is a repository asset with what code scanning needs.
type RepositoryRef struct {
	AssetID       shared.ID
	Name          string
	DefaultBranch string
	Visibility    string
	CloneURL      string
}

// Repository stores code scanning settings and branch states. Every method
// is scoped to the tenant.
type Repository interface {
	// GetSettings returns the tenant template (assetID nil) or a
	// repository's own settings; nil, nil when there are none.
	GetSettings(ctx context.Context, tenantID shared.ID, assetID *shared.ID) (*Settings, error)
	// UpsertSettings stores the template or a repository's settings.
	UpsertSettings(ctx context.Context, s *Settings) error
	// DeleteSettings removes a repository's own settings (it then inherits
	// the template).
	DeleteSettings(ctx context.Context, tenantID, assetID shared.ID) error
	// GetRepository returns a repository asset of the tenant (ErrNotFound
	// for any other asset type or tenant).
	GetRepository(ctx context.Context, tenantID, assetID shared.ID) (*RepositoryRef, error)
	// ListRepositories lists the tenant's repositories within a data scope
	// (nil: unrestricted), by name, and the total.
	ListRepositories(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit, offset int) ([]RepositoryRef, int, error)
	// RepositorySettings returns the repositories' own settings by asset id.
	RepositorySettings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]Settings, error)
	// Branches returns the repositories' branches by asset id.
	Branches(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID][]Branch, error)
	// EnsureDefaultBranch records the repository's default branch when no
	// branch of that name is known yet.
	EnsureDefaultBranch(ctx context.Context, tenantID, assetID shared.ID, name string) error
	// QueueFullScan marks branches of the repository queued for a full
	// scan with a trigger, skipping those already queued or running. It
	// returns how many were queued.
	QueueFullScan(ctx context.Context, tenantID, assetID shared.ID, branchIDs []shared.ID, trigger string) (int, error)
}

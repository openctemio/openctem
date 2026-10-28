package aianalysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AttestationPeriod is how long an owner's attestation lasts: past it the
// analyst pauses until an owner attests again.
const AttestationPeriod = 90 * 24 * time.Hour

// Errors.
var (
	ErrAnalystNotFound = fmt.Errorf("%w: AI analyst not found", shared.ErrNotFound)
	ErrRunNotFound     = fmt.Errorf("%w: AI run not found", shared.ErrNotFound)
	// ErrRunInFlight: a run of this use case for this subject is live.
	ErrRunInFlight = fmt.Errorf("%w: an AI run for this subject is already in progress", shared.ErrConflict)
	// ErrOwnerRequired: an analyst keeps at least one accountable owner.
	ErrOwnerRequired = fmt.Errorf("%w: an AI analyst needs at least one accountable owner", shared.ErrValidation)
	// ErrNotAllowed: the analyst's effective permissions do not allow the
	// action, or the subject is outside its scope.
	ErrNotAllowed = fmt.Errorf("%w: the AI analyst may not do this", shared.ErrForbidden)
)

// PausedError says why an analyst does not run now.
type PausedError struct{ Reason PauseReason }

func (e *PausedError) Error() string { return "the AI analyst is paused: " + string(e.Reason) }

// Is matches shared.ErrConflict (the request is fine, the analyst's state is not).
func (e *PausedError) Is(target error) bool { return target == shared.ErrConflict }

// Preset names the managed role an analyst holds.
type Preset string

const (
	// PresetSuggest: reads, comments and opens approval requests. Every
	// change it would make is written as a comment for a person.
	PresetSuggest Preset = "suggest"
	// PresetTriage: also confirms, moves status, raises severity and assigns.
	// Changes that lower risk still always become approval requests.
	PresetTriage Preset = "triage"
	// PresetCustom: an administrator gave the analyst another custom role;
	// the ceiling and the deny list still apply.
	PresetCustom Preset = "custom"
)

// ParsePreset validates a preset an administrator may pick.
func ParsePreset(s string) (Preset, error) {
	switch Preset(s) {
	case PresetSuggest, PresetTriage:
		return Preset(s), nil
	}
	return "", fmt.Errorf("%w: unknown AI analyst preset", shared.ErrValidation)
}

// Role templates of the presets (permission.AIAnalystTemplates; a test keeps
// the two in step).
const (
	templateSuggest = "ai-analyst-suggest"
	templateTriage  = "ai-analyst-triage"
)

// TemplateID is the role template behind a preset.
func (p Preset) TemplateID() string {
	switch p {
	case PresetSuggest:
		return templateSuggest
	case PresetTriage:
		return templateTriage
	}
	return ""
}

// Status is whether an analyst runs.
type Status string

const (
	StatusActive   Status = "active"
	StatusPaused   Status = "paused"
	StatusDisabled Status = "disabled"
)

// PauseReason says why an analyst is paused or disabled.
type PauseReason string

const (
	PauseNoActiveOwner      PauseReason = "no_active_owner"
	PauseAttestationExpired PauseReason = "attestation_expired"
	PauseAdmin              PauseReason = "admin"
	PauseNoPermissions      PauseReason = "no_permissions"
)

// OwnerKind is a person or a team.
type OwnerKind string

const (
	OwnerUser OwnerKind = "user"
	OwnerTeam OwnerKind = "team"
)

// OwnerRef names one accountable owner (also the snapshot on a run and in
// provenance).
type OwnerRef struct {
	Kind OwnerKind `json:"kind"`
	ID   shared.ID `json:"id"`
	Name string    `json:"name"`
}

// Analyst is the AI profile of a service account.
type Analyst struct {
	ID               shared.ID // the service account's user id
	TenantID         shared.ID
	Name             string
	Description      string
	Preset           Preset
	Status           Status
	PauseReason      PauseReason
	DataClassCeiling DataClass
	Executor         Executor
	RunsPerHour      int
	ActionsPerHour   int
	TokensMonth      int
	AttestedAt       time.Time
	AttestedBy       *shared.ID
	AttestDueAt      time.Time
	Owners           []OwnerRef
	CreatedBy        *shared.ID
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Defaults for a new analyst.
const (
	DefaultRunsPerHour    = 60
	DefaultActionsPerHour = 200
)

// HealthReason is why an active analyst must pause now ("" when it may run).
// activeOwners is the number of accountable owners that are active now.
func (a *Analyst) HealthReason(now time.Time, activeOwners int) PauseReason {
	switch {
	case activeOwners == 0:
		return PauseNoActiveOwner
	case !now.Before(a.AttestDueAt):
		return PauseAttestationExpired
	}
	return ""
}

// AccountableText is the owners as one display line ("Team X, Ann").
func AccountableText(owners []OwnerRef) string {
	names := make([]string, 0, len(owners))
	for _, o := range owners {
		names = append(names, o.Name)
	}
	return strings.Join(names, ", ")
}

// The deny list: never effective for an analyst, whatever its role says.
// Approving, resolving, deleting, exporting, revealing secrets, bulk changes
// and administering the organization stay with people.
var deniedExact = map[string]bool{
	string(permission.FindingsVerify):            true,
	string(permission.FindingsFixApply):          true,
	string(permission.FindingsBulkUpdate):        true,
	string(permission.CredentialsReveal):         true,
	string(permission.EvidenceReveal):            true,
	string(permission.FindingsLifecyclesWrite):   true,
	string(permission.FindingsRetestChecksWrite): true,
}

var deniedPrefixes = []string{
	"settings:", "team:", "integrations:", "audit:", "sensors:", "service_accounts:",
	"findings:suppressions:", "scans:",
}

var deniedSuffixes = []string{":approve", ":delete", ":export", ":reveal"}

// Denied reports a permission an analyst never holds.
func Denied(p string) bool {
	if deniedExact[p] {
		return true
	}
	if p == "scans:read" {
		return false
	}
	for _, pre := range deniedPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	for _, suf := range deniedSuffixes {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

// Effective is what an analyst may do: its role's permissions, kept only
// where at least one accountable person holds them too (ceilingAll: one of
// them is an owner or administrator and holds everything), minus the deny
// list. Sorted.
func Effective(role []string, ceilingAll bool, ceiling []string) []string {
	held := make(map[string]bool, len(ceiling))
	for _, p := range ceiling {
		held[p] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(role))
	for _, p := range role {
		if seen[p] || Denied(p) || (!ceilingAll && !held[p]) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// AboveCeiling lists the role permissions no accountable person holds (the
// reason an assignment is refused). Denied permissions are not listed: they
// are dropped, not refused.
func AboveCeiling(role []string, ceilingAll bool, ceiling []string) []string {
	if ceilingAll {
		return nil
	}
	held := make(map[string]bool, len(ceiling))
	for _, p := range ceiling {
		held[p] = true
	}
	var out []string
	for _, p := range role {
		if !held[p] && !Denied(p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

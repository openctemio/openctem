package remediation

// Remediation suggestions: docs/rfcs/RFC-098-remediation-tasks.md §5.
//
// Algorithms only propose. A suggestion is a stored proposal a person
// accepts, dismisses (with a reason) or snoozes; nothing here creates an
// action, a task or a membership.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// SuggestionKind is what a suggestion proposes.
type SuggestionKind string

const (
	// SuggestionNewGroup: findings share a fix that has no action yet.
	SuggestionNewGroup SuggestionKind = "new_group"
	// SuggestionJoin: findings with the key of an accepted action join an
	// active task of that action with the same owner.
	SuggestionJoin SuggestionKind = "join"
	// SuggestionTaskRoute: findings with the key of an accepted action and
	// no task for their owner get a new task.
	SuggestionTaskRoute SuggestionKind = "task_route"
)

// IsValid reports whether k is a known kind.
func (k SuggestionKind) IsValid() bool {
	switch k {
	case SuggestionNewGroup, SuggestionJoin, SuggestionTaskRoute:
		return true
	}
	return false
}

// SuggestionState is where a suggestion is in its lifecycle.
type SuggestionState string

const (
	SuggestionProposed   SuggestionState = "proposed"
	SuggestionAccepted   SuggestionState = "accepted"
	SuggestionDismissed  SuggestionState = "dismissed"
	SuggestionSnoozed    SuggestionState = "snoozed"
	SuggestionSuperseded SuggestionState = "superseded"
	SuggestionExpired    SuggestionState = "expired"
)

// IsValid reports whether s is a known state.
func (s SuggestionState) IsValid() bool {
	switch s {
	case SuggestionProposed, SuggestionAccepted, SuggestionDismissed, SuggestionSnoozed, SuggestionSuperseded, SuggestionExpired:
		return true
	}
	return false
}

// IsOpen reports whether a person can still decide on the suggestion.
func (s SuggestionState) IsOpen() bool { return s == SuggestionProposed || s == SuggestionSnoozed }

// DismissReason is why a person dismissed a suggestion.
type DismissReason string

const (
	DismissWrongGrouping  DismissReason = "wrong_grouping"
	DismissNotActionable  DismissReason = "not_actionable"
	DismissAlreadyTracked DismissReason = "already_tracked_elsewhere"
	DismissWrongOwner     DismissReason = "wrong_owner"
	DismissTooSmall       DismissReason = "too_small"
	DismissAcceptedRisk   DismissReason = "accepted_risk"
	DismissOther          DismissReason = "other"
)

// IsValid reports whether r is a known reason.
func (r DismissReason) IsValid() bool {
	switch r {
	case DismissWrongGrouping, DismissNotActionable, DismissAlreadyTracked, DismissWrongOwner,
		DismissTooSmall, DismissAcceptedRisk, DismissOther:
		return true
	}
	return false
}

// Generator settings.
const (
	// AlgorithmDeterministic names the key-based generator; its version
	// changes when its rules change.
	AlgorithmDeterministic        = "deterministic"
	AlgorithmDeterministicVersion = 2
	// MinGroupMembers is the smallest new group suggested, unless a member
	// is P0 or in KEV (then one is enough).
	MinGroupMembers = 2
	// MinConfidence hides suggestions the generator is not sure enough of.
	MinConfidence = 0.6
	// DailySurfaceCap bounds the new suggestions a tenant sees per day; the
	// rest wait, by rank, for the next day.
	DailySurfaceCap = 50
	// MaxSuggestionMembers bounds the findings one suggestion carries.
	MaxSuggestionMembers = 2000
	// MaxSnooze bounds a snooze.
	MaxSnooze = 180 * 24 * time.Hour
)

// Owner is who a partition of findings would be routed to: the asset's
// primary owner (a user and/or a group) or nobody (the default queue).
type Owner struct {
	UserID  *shared.ID
	GroupID *shared.ID
}

// Key is a stable string for grouping and fingerprints.
func (o Owner) Key() string {
	u, g := "", ""
	if o.UserID != nil {
		u = o.UserID.String()
	}
	if o.GroupID != nil {
		g = o.GroupID.String()
	}
	return u + "/" + g
}

// IsNone reports a finding with no owner (default queue).
func (o Owner) IsNone() bool { return o.UserID == nil && o.GroupID == nil }

// Candidate is one open, keyed finding without a primary task.
type Candidate struct {
	FindingID     shared.ID
	Key           string
	Title         string
	AssetID       *shared.ID
	Owner         Owner
	PriorityClass string
	Severity      string
	InKEV         bool
	SLADeadline   *time.Time
	RiskPoints    int
	// RuleID and FindingTitle feed the confidence of a solution-text group:
	// one rule and one vulnerability make "one fix" more certain.
	RuleID       string
	FindingTitle string
}

// IsUrgent reports a P0 or KEV finding.
func (c Candidate) IsUrgent() bool { return c.PriorityClass == "P0" || c.InKEV }

// AcceptedAction is an action that exists for a key, with its live tasks.
type AcceptedAction struct {
	ID    shared.ID
	Key   string
	Title string
	Tasks []ActionTask
	// AutoJoin: a person opted in to new findings with this key joining
	// the owner's live task without a suggestion.
	AutoJoin bool
}

// ActionTask is a live (non-terminal) task of an accepted action.
type ActionTask struct {
	ID    shared.ID
	Owner Owner
	State TaskState
}

// Partition is the findings of a suggestion that go to one owner.
type Partition struct {
	Owner      Owner       `json:"-"`
	OwnerUser  string      `json:"owner_user_id,omitempty"`
	OwnerGroup string      `json:"owner_group_id,omitempty"`
	OwnerRule  string      `json:"owner_rule"` // asset_owner | default_queue
	FindingIDs []shared.ID `json:"finding_ids"`
	RiskPoints int         `json:"risk_points"`
}

// RiskParts counts the members per priority class.
type RiskParts struct {
	P0         int `json:"p0"`
	P1         int `json:"p1"`
	P2         int `json:"p2"`
	P3         int `json:"p3"`
	Unclassed  int `json:"unclassified"`
	KEV        int `json:"kev"`
	AssetCount int `json:"assets"`
}

// Suggestion is one proposal.
type Suggestion struct {
	ID               shared.ID
	TenantID         shared.ID
	Kind             SuggestionKind
	Algorithm        string
	AlgorithmVersion int
	Key              string
	KeyKind          string
	Title            string
	Identity         string
	TargetActionID   *shared.ID
	TargetTaskID     *shared.ID
	Partitions       []Partition
	FindingIDs       []shared.ID
	MemberCount      int
	Truncated        int
	RiskPoints       int
	RiskParts        RiskParts
	HasUrgent        bool
	EarliestDeadline *time.Time
	Confidence       float64
	FixSpec          map[string]any
	State            SuggestionState
	DismissReason    DismissReason
	StateNote        string
	DecidedBy        *shared.ID
	DecidedAt        *time.Time
	SnoozedUntil     *time.Time
	SurfacedAt       *time.Time
	Version          int
	CreatedAt        time.Time
	UpdatedAt        time.Time

	// HiddenMembers is set per request: members outside the caller's scope
	// (the counts above are then over the visible ones).
	HiddenMembers int
}

// Errors.
var (
	ErrSuggestionNotFound = fmt.Errorf("%w: suggestion not found", shared.ErrNotFound)
	// ErrSuggestionDecided: someone already accepted, dismissed or the
	// generator expired it.
	ErrSuggestionDecided = fmt.Errorf("%w: the suggestion was already decided or has changed; reload it", shared.ErrConflict)
	// ErrSuggestionHiddenMembers: a restricted caller may not decide on a
	// suggestion with findings outside their scope.
	ErrSuggestionHiddenMembers = fmt.Errorf("%w: the suggestion has findings outside your access; ask someone who can see all of them", shared.ErrForbidden)
)

// Identity is the stable identity of a suggestion: what it proposes, not its
// current members. A new run updates the open suggestion with the same
// identity instead of adding one.
func Identity(kind SuggestionKind, key string, targetAction, targetTask *shared.ID, owner Owner) string {
	parts := []string{string(kind), key}
	switch kind {
	case SuggestionJoin:
		parts = append(parts, idOrEmpty(targetTask))
	case SuggestionTaskRoute:
		parts = append(parts, idOrEmpty(targetAction), owner.Key())
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func idOrEmpty(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// Basis factors: why the generator believes one fix closes every finding of
// a suggestion. Stored in fix_spec.basis so the console can explain the
// confidence in words.
const (
	BasisSamePackageTarget = "same_package_target"
	BasisSameSecretValue   = "same_secret_value"
	BasisSameSolutionText  = "same_specific_solution_text"
	BasisSameRule          = "same_rule"
	BasisSameFindingTitle  = "same_finding_title"
)

// maxBasisRules bounds the rule ids a suggestion lists in fix_spec.
const maxBasisRules = 5

// KeyConfidence is the floor of how sure a key is to mean "one fix": an exact
// package target or secret is certain; a specific solution text starts at
// 0.6 and gains from the members (Confidence).
func KeyConfidence(key string) float64 {
	switch KeyKind(key) {
	case KindUpgrade, KindRotate:
		return 1.0
	case KindSol:
		return 0.6
	}
	return 0.5
}

// Confidence is how sure the generator is that one fix closes every one of
// these findings, with the factors behind it. An exact package target or
// secret value is certain. A specific solution text is 0.6, plus 0.2 when
// every finding comes from one scanner rule and 0.1 when every finding is the
// same vulnerability (same title); the factors not met are left out.
func Confidence(key string, cs []Candidate) (float64, []string) {
	switch KeyKind(key) {
	case KindUpgrade:
		return 1.0, []string{BasisSamePackageTarget}
	case KindRotate:
		return 1.0, []string{BasisSameSecretValue}
	case KindSol:
		conf, basis := 0.6, []string{BasisSameSolutionText}
		rules, titles := map[string]bool{}, map[string]bool{}
		for _, c := range cs {
			rules[strings.ToLower(strings.TrimSpace(c.RuleID))] = true
			titles[strings.ToLower(strings.TrimSpace(c.FindingTitle))] = true
		}
		if len(rules) == 1 && !rules[""] {
			conf += 0.2
			basis = append(basis, BasisSameRule)
		}
		if len(titles) == 1 && !titles[""] {
			conf += 0.1
			basis = append(basis, BasisSameFindingTitle)
		}
		return math.Round(conf*100) / 100, basis
	}
	return KeyConfidence(key), nil
}

// basisRules lists up to maxBasisRules distinct rule ids, sorted.
func basisRules(cs []Candidate) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		r := strings.TrimSpace(c.RuleID)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Strings(out)
	if len(out) > maxBasisRules {
		out = out[:maxBasisRules]
	}
	return out
}

// FixSpecForKey describes the fix a key names, for the fix steps a person
// sees (the console renders the ecosystem's command).
func FixSpecForKey(key string) map[string]any {
	parts := strings.Split(key, ":")
	switch KeyKind(key) {
	case KindUpgrade:
		if len(parts) == 4 {
			return map[string]any{"kind": KindUpgrade, "ecosystem": parts[1],
				"package": strings.ReplaceAll(parts[2], "~", "/"), "target_version": parts[3]}
		}
	case KindRotate:
		if len(parts) == 3 {
			fp := parts[2]
			if len(fp) > 8 {
				fp = fp[:8]
			}
			return map[string]any{"kind": KindRotate, "secret_fingerprint_prefix": fp}
		}
	case KindSol:
		if len(parts) == 3 {
			return map[string]any{"kind": KindSol, "source": parts[1]}
		}
	}
	return map[string]any{"kind": KeyKind(key)}
}

// BuildSuggestions turns the candidates into suggestions. Rules:
//
//   - a key with no accepted action → one new_group suggestion, its findings
//     partitioned by owner; at least MinGroupMembers findings unless one is
//     urgent (P0 or KEV);
//   - a key with an accepted action → per owner, a join suggestion into the
//     action's live task with the same owner, or a task_route suggestion for
//     a new task when there is none;
//   - excluded (finding, key) pairs are left out: a person removed them
//     from that fix before;
//   - suggestions below MinConfidence are dropped.
//
// The result is ranked: risk reduced, then members, then the earliest
// deadline, then the key (stable).
func BuildSuggestions(tenantID shared.ID, cands []Candidate, accepted map[string]AcceptedAction, excluded map[string]map[shared.ID]bool) []Suggestion {
	byKey := map[string][]Candidate{}
	for _, c := range cands {
		if excluded[c.Key][c.FindingID] {
			continue
		}
		byKey[c.Key] = append(byKey[c.Key], c)
	}
	out := make([]Suggestion, 0, len(byKey))
	for key, cs := range byKey {
		conf := KeyConfidence(key)
		if conf < MinConfidence {
			continue
		}
		action, has := accepted[key]
		if !has {
			s := newSuggestion(tenantID, SuggestionNewGroup, key, cs, nil, nil, Owner{})
			if s.MemberCount < MinGroupMembers && !s.HasUrgent {
				continue
			}
			out = append(out, s)
			continue
		}
		byOwner := map[string][]Candidate{}
		owners := map[string]Owner{}
		for _, c := range cs {
			byOwner[c.Owner.Key()] = append(byOwner[c.Owner.Key()], c)
			owners[c.Owner.Key()] = c.Owner
		}
		for ok, group := range byOwner {
			owner := owners[ok]
			actionID := action.ID
			if task := liveTaskFor(action, owner); task != nil {
				tid := task.ID
				out = append(out, newSuggestion(tenantID, SuggestionJoin, key, group, &actionID, &tid, owner))
				continue
			}
			out = append(out, newSuggestion(tenantID, SuggestionTaskRoute, key, group, &actionID, nil, owner))
		}
	}
	RankSuggestions(out)
	return out
}

// liveTaskFor returns the action's live task with exactly this owner.
func liveTaskFor(a AcceptedAction, o Owner) *ActionTask {
	for i := range a.Tasks {
		t := &a.Tasks[i]
		if t.State.IsTerminal() {
			continue
		}
		if t.Owner.Key() == o.Key() {
			return t
		}
	}
	return nil
}

func newSuggestion(tenantID shared.ID, kind SuggestionKind, key string, cs []Candidate, actionID, taskID *shared.ID, owner Owner) Suggestion {
	// Highest risk first, so a truncated suggestion keeps the findings
	// that matter most.
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].RiskPoints != cs[j].RiskPoints {
			return cs[i].RiskPoints > cs[j].RiskPoints
		}
		return cs[i].FindingID.String() < cs[j].FindingID.String()
	})
	s := Suggestion{
		TenantID: tenantID, Kind: kind, Algorithm: AlgorithmDeterministic, AlgorithmVersion: AlgorithmDeterministicVersion,
		Key: key, KeyKind: KeyKind(key), TargetActionID: actionID, TargetTaskID: taskID,
		FixSpec: FixSpecForKey(key), State: SuggestionProposed,
	}
	if len(cs) > MaxSuggestionMembers {
		s.Truncated = len(cs) - MaxSuggestionMembers
		cs = cs[:MaxSuggestionMembers]
	}
	assets := map[shared.ID]bool{}
	parts := map[string]*Partition{}
	var order []string
	for _, c := range cs {
		if s.Title == "" || c.Title < s.Title {
			s.Title = c.Title
		}
		s.FindingIDs = append(s.FindingIDs, c.FindingID)
		s.RiskPoints += c.RiskPoints
		if c.IsUrgent() {
			s.HasUrgent = true
		}
		if c.InKEV {
			s.RiskParts.KEV++
		}
		switch c.PriorityClass {
		case "P0":
			s.RiskParts.P0++
		case "P1":
			s.RiskParts.P1++
		case "P2":
			s.RiskParts.P2++
		case "P3":
			s.RiskParts.P3++
		default:
			s.RiskParts.Unclassed++
		}
		if c.AssetID != nil {
			assets[*c.AssetID] = true
		}
		if c.SLADeadline != nil && (s.EarliestDeadline == nil || c.SLADeadline.Before(*s.EarliestDeadline)) {
			d := *c.SLADeadline
			s.EarliestDeadline = &d
		}
		ok := c.Owner.Key()
		p := parts[ok]
		if p == nil {
			p = &Partition{Owner: c.Owner, OwnerRule: "asset_owner"}
			if c.Owner.IsNone() {
				p.OwnerRule = "default_queue"
			}
			if c.Owner.UserID != nil {
				p.OwnerUser = c.Owner.UserID.String()
			}
			if c.Owner.GroupID != nil {
				p.OwnerGroup = c.Owner.GroupID.String()
			}
			parts[ok] = p
			order = append(order, ok)
		}
		p.FindingIDs = append(p.FindingIDs, c.FindingID)
		p.RiskPoints += c.RiskPoints
	}
	sort.Strings(order)
	for _, ok := range order {
		s.Partitions = append(s.Partitions, *parts[ok])
	}
	sort.SliceStable(s.Partitions, func(i, j int) bool { return s.Partitions[i].RiskPoints > s.Partitions[j].RiskPoints })
	s.MemberCount = len(s.FindingIDs)
	s.RiskParts.AssetCount = len(assets)
	var basis []string
	s.Confidence, basis = Confidence(key, cs)
	if len(basis) > 0 {
		s.FixSpec["basis"] = basis
	}
	if rules := basisRules(cs); len(rules) > 0 {
		s.FixSpec["rule_ids"] = rules
	}
	s.Identity = Identity(kind, key, actionID, taskID, owner)
	return s
}

// RankSuggestions orders suggestions: risk reduced, members, earliest
// deadline, key.
func RankSuggestions(ss []Suggestion) {
	sort.SliceStable(ss, func(i, j int) bool {
		a, b := ss[i], ss[j]
		if a.RiskPoints != b.RiskPoints {
			return a.RiskPoints > b.RiskPoints
		}
		if a.MemberCount != b.MemberCount {
			return a.MemberCount > b.MemberCount
		}
		switch {
		case a.EarliestDeadline != nil && b.EarliestDeadline == nil:
			return true
		case a.EarliestDeadline == nil && b.EarliestDeadline != nil:
			return false
		case a.EarliestDeadline != nil && !a.EarliestDeadline.Equal(*b.EarliestDeadline):
			return a.EarliestDeadline.Before(*b.EarliestDeadline)
		}
		return a.Identity < b.Identity
	})
}

// DismissedSnapshot is what a dismissed suggestion looked like when a
// person dismissed it.
type DismissedSnapshot struct {
	MemberCount int
	RiskPoints  int
	HasUrgent   bool
}

// MateriallyChanged reports whether a suggestion changed enough since a
// person dismissed it to be proposed again: members up by half or by ten,
// risk doubled, or a member became P0 or KEV. Otherwise the dismissal holds.
func MateriallyChanged(prev DismissedSnapshot, now Suggestion) bool {
	switch {
	case now.MemberCount*2 >= prev.MemberCount*3 && now.MemberCount > prev.MemberCount:
		return true
	case now.MemberCount >= prev.MemberCount+10:
		return true
	case prev.RiskPoints > 0 && now.RiskPoints >= 2*prev.RiskPoints:
		return true
	case now.HasUrgent && !prev.HasUrgent:
		return true
	}
	return false
}

// SuggestionFilter narrows a suggestion list.
type SuggestionFilter struct {
	States  []SuggestionState
	Kinds   []SuggestionKind
	KeyKind string
	MinRisk int
	Search  string
	// IncludeQueued lists proposed suggestions held back by the daily cap.
	IncludeQueued bool
	Scope         *shared.DataScope
}

// SuggestionCounts summarizes a tenant's open suggestions.
type SuggestionCounts struct {
	Proposed int            `json:"proposed"`
	Queued   int            `json:"queued"`
	Snoozed  int            `json:"snoozed"`
	ByKind   map[string]int `json:"by_kind"`
}

// RunStats is the outcome of one generator run.
type RunStats struct {
	Candidates int `json:"candidates"`
	Created    int `json:"created"`
	Updated    int `json:"updated"`
	Expired    int `json:"expired"`
	Surfaced   int `json:"surfaced"`
	Held       int `json:"held"` // dismissed and not materially changed
	Woken      int `json:"woken"`
	AutoJoined int `json:"auto_joined"`
}

// ErrRunTooSoon: a refresh asked for right after another run.
var ErrRunTooSoon = errors.New("suggestions were refreshed less than a minute ago")

// SuggestionDecision is a person's decision on a suggestion.
type SuggestionDecision struct {
	State        SuggestionState
	Reason       DismissReason
	Note         string
	SnoozedUntil *time.Time
	ActorID      *shared.ID
}

// SuggestionRepository stores suggestions. Every method is scoped to one
// tenant except the ones named ForPlatform.
type SuggestionRepository interface {
	TenantsWithKeysForPlatform(ctx context.Context) ([]shared.ID, error)
	Candidates(ctx context.Context, tenantID shared.ID) ([]Candidate, error)
	AcceptedActions(ctx context.Context, tenantID shared.ID, keys []string) (map[string]AcceptedAction, error)
	Exclusions(ctx context.Context, tenantID shared.ID) (map[string]map[shared.ID]bool, error)
	ApplyRun(ctx context.Context, tenantID shared.ID, ss []Suggestion, now time.Time) (RunStats, error)
	RunInfo(ctx context.Context, tenantID shared.ID) (lastRun, lastDigest *time.Time, err error)
	SurfacedSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error)
	MarkDigest(ctx context.Context, tenantID shared.ID, at time.Time) error
	ListSuggestions(ctx context.Context, tenantID shared.ID, f SuggestionFilter, page pagination.Pagination) (pagination.Result[*Suggestion], error)
	GetSuggestion(ctx context.Context, tenantID, id shared.ID, scope *shared.DataScope) (*Suggestion, error)
	SuggestionMembers(ctx context.Context, tenantID, id shared.ID, scope *shared.DataScope, page pagination.Pagination) (pagination.Result[SuggestionMember], error)
	DecideSuggestion(ctx context.Context, tenantID, id shared.ID, version int, d SuggestionDecision) (*Suggestion, error)
	CountSuggestions(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (SuggestionCounts, error)
	AcceptSuggestion(ctx context.Context, plan AcceptPlan) (*AcceptResult, error)
	AutoJoin(ctx context.Context, tenantID, actionID, taskID shared.ID, findingIDs []shared.ID) (int, error)
	SetAutoJoin(ctx context.Context, tenantID, actionID shared.ID, on bool, actor *shared.ID) (*Action, error)
	// IsGroupMember reports whether the user belongs to the tenant's group.
	IsGroupMember(ctx context.Context, tenantID, groupID, userID shared.ID) (bool, error)
	// OwnsFindingAssets reports whether every finding is on an asset the
	// user owns (primary or secondary), directly or through a group.
	OwnsFindingAssets(ctx context.Context, tenantID, userID shared.ID, findingIDs []shared.ID) (bool, error)
}

// Accept limits.
const (
	// AutoJoinDailyCap bounds the findings one action auto-joins per day;
	// beyond it, joins fall back to suggestions.
	AutoJoinDailyCap = 200
	// MaxBulkAccept bounds one bulk accept.
	MaxBulkAccept = 50
	// MaxBulkAcceptFindings bounds the findings of one bulk accept.
	MaxBulkAcceptFindings = 5000
)

// AutoJoinAllowed reports whether a key kind may auto-join: exact identities
// only (a package upgrade or one secret), never text matches.
func AutoJoinAllowed(kind string) bool { return kind == KindUpgrade || kind == KindRotate }

// CanAutoJoinInto reports whether auto-join may add findings to a task in
// this state: an open or in-progress task only. A verifying, held or closed
// task gets a suggestion instead.
func CanAutoJoinInto(s TaskState) bool { return s == TaskStateOpen || s == TaskStateInProgress }

// AcceptPlanTask is one task an accept creates.
type AcceptPlanTask struct {
	// ID is the new task's id (the repository sets one when zero).
	ID         shared.ID
	Title      string
	Owner      Owner
	FindingIDs []shared.ID
	Deadline   *time.Time
}

// AcceptPlan is what accepting a suggestion stores, in one transaction.
type AcceptPlan struct {
	TenantID     shared.ID
	SuggestionID shared.ID
	Version      int
	Kind         SuggestionKind
	// NewAction is set for a new group; ActionID for join and task_route.
	NewAction *Action
	ActionID  *shared.ID
	// TargetTaskID: the task a join adds to.
	TargetTaskID *shared.ID
	JoinIDs      []shared.ID
	Tasks        []AcceptPlanTask
	// Excluded are the findings the person removed: remembered for the key.
	Excluded []shared.ID
	AutoJoin bool
	ActorID  *shared.ID
	// Conflicts resolves findings taken by another active task since the
	// suggestion was made (zero value: refuse them).
	Conflicts ConflictResolution
}

// AcceptResult is what an accept created.
type AcceptResult struct {
	SuggestionID shared.ID   `json:"suggestion_id"`
	ActionID     shared.ID   `json:"action_id"`
	TaskIDs      []shared.ID `json:"task_ids"`
	Joined       int         `json:"joined"`
	// Dropped are findings that closed since the suggestion was made; they
	// were left out.
	Dropped []shared.ID `json:"dropped"`
	// Skipped are findings of another active task left out as asked.
	Skipped []shared.ID `json:"skipped"`
	// Moved counts findings moved out of another task as asked.
	Moved int `json:"moved"`
	// Claim reports the moves (for the audit log and notifications).
	Claim ClaimReport `json:"-"`
}

// ErrNothingToAccept: every finding of the suggestion was removed, closed or
// skipped.
var ErrNothingToAccept = fmt.Errorf("%w: no finding is left to accept", shared.ErrValidation)

// SuggestionMember is one finding of a suggestion with what a person needs
// to judge it: where it is, the rule, the installed version, the scanner's
// advice and the task that claimed it since the suggestion was made.
// Scanner text (Recommendation, FixCode) is plain text, capped, with secret
// shapes redacted by the service.
type SuggestionMember struct {
	TaskMember
	RuleID           string
	CWEIDs           []string
	FilePath         string
	StartLine        int
	Branch           string
	NetworkPort      int
	NetworkTransport string
	// LocationTargets are the first affected targets a finding without a
	// file names (a URL, host:port).
	LocationTargets  []string
	AssetCriticality string
	PackageName      string
	InstalledVersion string
	Recommendation   string
	FixCode          string
	// ActiveTask is the active task the finding is the primary member of,
	// when one claimed it since the suggestion was made.
	ActiveTask *TaskRef
}

// TaskRef names a task.
type TaskRef struct {
	ID    shared.ID
	Title string
}

// Suggestion member text caps (runes).
const (
	MaxMemberRecommendation = 2000
	MaxMemberFixCode        = 4000
	MaxMemberTargets        = 5
)

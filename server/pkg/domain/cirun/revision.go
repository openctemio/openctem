package cirun

// Verdict revisions and re-judging a stored run after a decision
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, "Verdict
// revisions").
//
// A run's first verdict is revision 1 and never changes. When a person makes
// a final decision in the platform (a finding marked false positive or
// duplicate, a risk accepted with an end date, a suppression rule approved),
// the platform judges the run again on the findings it stored, with the
// decisions as they are now and with everything else exactly as the first
// verdict saw it (JudgeSnapshot): the policy as applied, the baseline
// comparison, and the run's own failures. Nothing the CI job sends takes
// part, and a policy change is not a decision: it applies to the next run.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Revision causes.
const (
	// RevisionCauseEvaluate: a CI job asked for the verdict.
	RevisionCauseEvaluate = "evaluate"
	// RevisionCauseDecision: a decision in the platform re-judged the run.
	RevisionCauseDecision = "decision"
)

// SnapshotVersion is the version of JudgeSnapshot this code writes; a
// snapshot of another version is not re-judged (fail closed).
const SnapshotVersion = 1

// MaxSnapshotNewFingerprints bounds the new fingerprints a snapshot keeps. A
// run with more new findings is not re-judged: its snapshot is marked
// incomplete and the developer pushes or re-runs as before.
const MaxSnapshotNewFingerprints = 10_000

// RejudgeWindow is how long after its verdict a run may be re-judged.
const RejudgeWindow = 14 * 24 * time.Hour

// MaxRejudgeRuns bounds the runs one decision re-judges.
const MaxRejudgeRuns = 500

// DefaultReopenLimit is how many blocked merge requests one person's
// decisions may reopen in an hour before the circuit breaker pauses them.
const DefaultReopenLimit = 20

// SnapshotPolicy is the part of the gate policy Evaluate reads, as it was
// applied to the run (after the repository file tightened it).
type SnapshotPolicy struct {
	Mode                 string      `json:"mode"`
	FailOnSeverity       string      `json:"fail_on_severity"`
	NewFindingsOnly      bool        `json:"new_findings_only"`
	FailOnKEV            bool        `json:"fail_on_kev"`
	EPSSThreshold        *float64    `json:"epss_threshold,omitempty"`
	FixableOnly          bool        `json:"fixable_only,omitempty"`
	BaselineSecretsBlock bool        `json:"baseline_secrets_block"`
	Modes                PolicyModes `json:"modes"`
}

// JudgeSnapshot is everything a run's verdict was computed with besides its
// findings and their decisions.
type JudgeSnapshot struct {
	Version      int            `json:"v"`
	Policy       SnapshotPolicy `json:"policy"`
	PolicySource string         `json:"policy_source"`
	RepoFile     string         `json:"repo_file,omitempty"`
	// AllNew: no baseline was known, every finding counted as new.
	AllNew bool `json:"all_new"`
	// NewFingerprints are the findings the change introduced (when not
	// AllNew). Incomplete: more than MaxSnapshotNewFingerprints, so the run
	// cannot be re-judged.
	NewFingerprints     []string   `json:"new_fingerprints,omitempty"`
	Incomplete          bool       `json:"incomplete,omitempty"`
	BaselineBranch      string     `json:"baseline_branch,omitempty"`
	BaselineKnown       bool       `json:"baseline_known"`
	BaselineSetAt       *time.Time `json:"baseline_set_at,omitempty"`
	BaselineEstablished bool       `json:"baseline_established,omitempty"`
	BaselineDueAt       *time.Time `json:"baseline_due_at,omitempty"`
	DefaultBranch       bool       `json:"default_branch"`
	// The run's own failures: a re-judge never clears them.
	ScanFailures        int               `json:"scan_failures"`
	UploadsNotApplied   int               `json:"uploads_not_applied"`
	NoResults           bool              `json:"no_results"`
	FailedCapabilities  []CapabilityState `json:"failed_capabilities,omitempty"`
	FindingsOverCap     bool              `json:"findings_over_cap"`
	MissingCapabilities []string          `json:"missing_capabilities,omitempty"`
}

// NewJudgeSnapshot records what in was computed with.
func NewJudgeSnapshot(in GateInput, repoFile string) JudgeSnapshot {
	p := in.Policy
	s := JudgeSnapshot{
		Version: SnapshotVersion,
		Policy: SnapshotPolicy{Mode: p.Mode, FailOnSeverity: p.FailOnSeverity, NewFindingsOnly: p.NewFindingsOnly,
			FailOnKEV: p.FailOnKEV, EPSSThreshold: p.EPSSThreshold, FixableOnly: p.FixableOnly,
			BaselineSecretsBlock: p.BaselineSecretsBlock, Modes: p.Modes},
		PolicySource: in.PolicySource, RepoFile: repoFile,
		AllNew:         in.NewFingerprints == nil,
		BaselineBranch: in.BaselineBranch, BaselineKnown: in.BaselineKnown, BaselineSetAt: in.BaselineSetAt,
		BaselineEstablished: in.BaselineEstablished, BaselineDueAt: in.BaselineDueAt, DefaultBranch: in.DefaultBranch,
		ScanFailures: in.ScanFailures, UploadsNotApplied: in.UploadsNotApplied, NoResults: in.NoResults,
		FailedCapabilities: in.FailedCapabilities, FindingsOverCap: in.FindingsOverCap,
		MissingCapabilities: in.MissingCapabilities,
	}
	if !s.AllNew {
		s.NewFingerprints = make([]string, 0, len(in.NewFingerprints))
		for fp, isNew := range in.NewFingerprints {
			if !isNew {
				continue
			}
			if len(s.NewFingerprints) == MaxSnapshotNewFingerprints {
				s.Incomplete = true
				s.NewFingerprints = nil
				break
			}
			s.NewFingerprints = append(s.NewFingerprints, fp)
		}
	}
	return s
}

// ErrNotRejudgeable: the run has no usable snapshot (judged before
// revisions existed, concluded by the sweeper, or too large).
var ErrNotRejudgeable = fmt.Errorf("%w: the CI run cannot be re-judged", shared.ErrConflict)

// ParseJudgeSnapshot reads a stored snapshot; ErrNotRejudgeable when there
// is none or it cannot be used.
func ParseJudgeSnapshot(raw []byte) (JudgeSnapshot, error) {
	var s JudgeSnapshot
	if len(raw) == 0 {
		return s, ErrNotRejudgeable
	}
	if err := json.Unmarshal(raw, &s); err != nil || s.Version != SnapshotVersion || s.Incomplete {
		return JudgeSnapshot{}, ErrNotRejudgeable
	}
	return s, nil
}

// Input rebuilds the gate input of the snapshot over the run's findings as
// they are now (their decisions included), with the break-glass active now.
func (s JudgeSnapshot) Input(findings []RunFinding, override *GateOverride, now time.Time, findingURL func(shared.ID) string) GateInput {
	var newSet map[string]bool
	if !s.AllNew {
		newSet = make(map[string]bool, len(s.NewFingerprints))
		for _, fp := range s.NewFingerprints {
			newSet[fp] = true
		}
	}
	p := s.Policy
	return GateInput{
		Policy: GatePolicy{Mode: p.Mode, FailOnSeverity: p.FailOnSeverity, NewFindingsOnly: p.NewFindingsOnly,
			FailOnKEV: p.FailOnKEV, EPSSThreshold: p.EPSSThreshold, FixableOnly: p.FixableOnly,
			BaselineSecretsBlock: p.BaselineSecretsBlock, Modes: p.Modes},
		PolicySource: s.PolicySource, Findings: findings, NewFingerprints: newSet,
		BaselineBranch: s.BaselineBranch, BaselineKnown: s.BaselineKnown, BaselineSetAt: s.BaselineSetAt,
		BaselineEstablished: s.BaselineEstablished, BaselineDueAt: s.BaselineDueAt, DefaultBranch: s.DefaultBranch,
		ScanFailures: s.ScanFailures, UploadsNotApplied: s.UploadsNotApplied, NoResults: s.NoResults,
		FailedCapabilities: s.FailedCapabilities, FindingsOverCap: s.FindingsOverCap,
		MissingCapabilities: s.MissingCapabilities, Override: override, Now: now, FindingURL: findingURL,
	}
}

// Rejudge judges a stored run again: the snapshot's inputs, the findings and
// decisions as they are now. Infrastructure reasons (scan failure, upload
// not applied, no results, capability failed or missing, too many findings)
// come from the snapshot and so are never cleared.
func Rejudge(s JudgeSnapshot, findings []RunFinding, override *GateOverride, now time.Time, findingURL func(shared.ID) string) GateVerdict {
	return Evaluate(s.Input(findings, override, now, findingURL))
}

// RevisionView is what a verdict says about the revision it is. It goes to
// the CI job and the merge request, which may be public: it names no person,
// only the role ("the security team") and counts.
type RevisionView struct {
	Number int    `json:"number"`
	Cause  string `json:"cause"`
	// Previous is the verdict this revision replaced.
	Previous string    `json:"previous,omitempty"`
	At       time.Time `json:"at"`
	// Decided counts, by decision, the findings that blocked the previous
	// verdict and no longer count.
	Decided map[string]int `json:"decided,omitempty"`
}

// VerdictRevision is one stored revision of a run's verdict.
type VerdictRevision struct {
	TenantID    shared.ID
	RunID       shared.ID
	Revision    int
	Verdict     string
	Detail      json.RawMessage
	Cause       string
	DecisionIDs []shared.ID
	ActorIDs    []shared.ID
	// Reopened: a decision turned a failing verdict into a passing one.
	Reopened  bool
	CreatedAt time.Time
}

// VerdictRecord is a verdict a CI job's evaluation stores, with what it was
// computed with.
type VerdictRecord struct {
	TenantID           shared.ID
	RunID              shared.ID
	Verdict            string
	Detail             []byte
	At                 time.Time
	ExpectFindings     int
	FailedCapabilities []string
	// Snapshot is the JudgeSnapshot JSON (nil: the run is never re-judged).
	Snapshot []byte
	// GateJobID is the CI job that asked for the verdict ("" keeps the one
	// recorded).
	GateJobID string
}

// RejudgeFilter selects the runs a decision may reopen.
type RejudgeFilter struct {
	// FindingID: runs that recorded this finding (on its asset).
	FindingID *shared.ID
	// AssetID: runs of this repository (a suppression rule bound to it).
	AssetID *shared.ID
	// AnyRepository: every repository of the tenant (a rule bound to none).
	AnyRepository bool
	// Since: evaluated or revised after this time.
	Since time.Time
	Limit int
}

// ErrReopenPaused: the person's decisions no longer reopen merge requests
// (circuit breaker); PausedNow says this decision tripped it.
type ErrReopenPaused struct{ PausedNow bool }

func (e *ErrReopenPaused) Error() string {
	return "the decisions of this person no longer reopen merge requests until an owner resumes them"
}

// RevisionAppend is one re-judge under the run's row lock.
type RevisionAppend struct {
	// Build computes the revision from the locked run; nil means nothing to
	// append (the run moved on, or the verdict did not change).
	Build func(locked *Run) (*VerdictRevision, error)
	// ActorID is the person whose decision this is; with ReopenLimit > 0 a
	// revision that reopens the run is refused (ErrReopenPaused) when that
	// person is paused or reached the limit in the last hour.
	ActorID     *shared.ID
	ReopenLimit int
}

// ReopenPause is a person whose decisions no longer reopen merge requests.
type ReopenPause struct {
	UserID   shared.ID `json:"user_id"`
	PausedAt time.Time `json:"paused_at"`
	Reopens  int       `json:"reopens"`
}

// RevisionRepository stores verdict revisions. Every method is
// tenant-scoped.
type RevisionRepository interface {
	// SaveVerdictRecord stores a CI job's verdict like SaveVerdict and
	// appends it as the run's next revision (cause evaluate) with its
	// snapshot and gate job.
	SaveVerdictRecord(ctx context.Context, rec VerdictRecord) error
	// RunSnapshot returns the run's JudgeSnapshot JSON (nil: none).
	RunSnapshot(ctx context.Context, tenantID, runID shared.ID) ([]byte, error)
	// RejudgeCandidates returns the latest run of each pull request and
	// pipeline whose verdict is fail, that is not a fork, whose commit is
	// verified, on GitHub or GitLab, judged or revised since f.Since, that
	// recorded f.FindingID (or is on f.AssetID), at most f.Limit.
	RejudgeCandidates(ctx context.Context, tenantID shared.ID, f RejudgeFilter) ([]Run, error)
	// AppendVerdictRevision locks the run row, builds the revision and
	// stores it as the run's current verdict, queuing its decoration.
	AppendVerdictRevision(ctx context.Context, tenantID, runID shared.ID, a RevisionAppend) (*VerdictRevision, error)
	// ListVerdictRevisions returns the run's revisions, oldest first.
	ListVerdictRevisions(ctx context.Context, tenantID, runID shared.ID) ([]VerdictRevision, error)
	// MarkGateJobRetried records that the platform retried the run's gate
	// job for revision; false when it already did for it or a later one.
	MarkGateJobRetried(ctx context.Context, tenantID, runID shared.ID, revision int) (bool, error)
	// ReopenOnDecision reads and SetReopenOnDecision writes the tenant's
	// switch.
	ReopenOnDecision(ctx context.Context, tenantID shared.ID) (bool, error)
	SetReopenOnDecision(ctx context.Context, tenantID shared.ID, on bool) error
	// ReopenPauses lists the paused people; ResumeReopen removes one pause
	// (false when there was none).
	ReopenPauses(ctx context.Context, tenantID shared.ID) ([]ReopenPause, error)
	ResumeReopen(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}

// DecidedByDecision counts, by decision, the findings that blocked prev and
// carry a decision now (the ids returned too, in order).
func DecidedByDecision(prev GateVerdict, findings []RunFinding, now time.Time) (map[string]int, []shared.ID) {
	blocking := map[string]bool{}
	for _, r := range prev.Reasons {
		if r.FindingID != "" && r.Mode == "" && blockingReason(r.Code) {
			blocking[r.FindingID] = true
		}
	}
	counts := map[string]int{}
	ids := []shared.ID{}
	for _, f := range findings {
		if !blocking[f.ID.String()] {
			continue
		}
		if d := Decision(f, now); d != "" {
			counts[d]++
			ids = append(ids, f.ID)
		}
	}
	return counts, ids
}

// SeriousReopen reports whether reopening a run whose previous verdict was
// prev unblocks a serious finding among ids: a secret, a known-exploited
// vulnerability or a critical one. The owners are told about those.
func SeriousReopen(prev GateVerdict, ids []shared.ID) bool {
	decided := make(map[string]bool, len(ids))
	for _, id := range ids {
		decided[id.String()] = true
	}
	for _, r := range prev.Reasons {
		if !decided[r.FindingID] || r.Mode != "" {
			continue
		}
		if r.Code == ReasonSecret || r.Code == ReasonKEV || severityRank[strings.ToLower(r.Severity)] >= severityRank["critical"] {
			return true
		}
	}
	return false
}

func blockingReason(code string) bool {
	switch code {
	case ReasonSecret, ReasonKEV, ReasonEPSS, ReasonSeverity:
		return true
	}
	return false
}

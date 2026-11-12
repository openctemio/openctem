package exploration

// Leads, links and verdicts: the exploration layer's own records
// (docs/architecture/exploration.md). A lead is an open question about one
// subject with a typed next action; links tie it to the evidence that
// justified it, to the run it was dispatched as and to what that run
// yielded; verdicts settle it and are never changed.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
)

// LeadState is where a lead is in its life.
type LeadState string

const (
	// StateProposed: suggested, not accepted yet (proposals by AI agents).
	StateProposed LeadState = "proposed"
	// StateAwaitingApproval: the action needs a person's approval first.
	StateAwaitingApproval LeadState = "awaiting_approval"
	// StateOpen: on the frontier, dispatched when its score and the caps allow.
	StateOpen LeadState = "open"
	// StateRunning: dispatched; waiting for its run to settle.
	StateRunning LeadState = "running"
	// StateBlocked: the dispatch gate or a guard refused it; rechecked later.
	StateBlocked LeadState = "blocked"
	// StateDone: settled with a positive result.
	StateDone LeadState = "done"
	// StateRefuted: settled; the question's answer is no.
	StateRefuted LeadState = "refuted"
	// StateExhausted: no further action may answer it (attempts or budget spent).
	StateExhausted LeadState = "exhausted"
	// StateDismissed: a person closed it without running it.
	StateDismissed LeadState = "dismissed"
	// StateSuperseded: its subject or question no longer holds.
	StateSuperseded LeadState = "superseded"
)

// LiveStates are the states that hold the question's dedup key.
var LiveStates = []LeadState{StateProposed, StateAwaitingApproval, StateOpen, StateRunning, StateBlocked}

// IsValid reports whether s is a known state.
func (s LeadState) IsValid() bool {
	switch s {
	case StateProposed, StateAwaitingApproval, StateOpen, StateRunning, StateBlocked,
		StateDone, StateRefuted, StateExhausted, StateDismissed, StateSuperseded:
		return true
	}
	return false
}

// Live reports whether the lead is still a question (not closed).
func (s LeadState) Live() bool {
	switch s {
	case StateProposed, StateAwaitingApproval, StateOpen, StateRunning, StateBlocked:
		return true
	}
	return false
}

// transitions are the moves a lead may make; a closed lead never moves.
var transitions = map[LeadState][]LeadState{
	StateProposed:         {StateOpen, StateAwaitingApproval, StateDismissed, StateSuperseded},
	StateAwaitingApproval: {StateOpen, StateDismissed, StateSuperseded},
	StateOpen:             {StateRunning, StateBlocked, StateAwaitingApproval, StateExhausted, StateDismissed, StateSuperseded},
	StateRunning:          {StateDone, StateRefuted, StateExhausted, StateOpen, StateBlocked, StateSuperseded},
	StateBlocked:          {StateOpen, StateAwaitingApproval, StateExhausted, StateDismissed, StateSuperseded},
}

// CanMove reports whether a lead in from may move to to.
func CanMove(from, to LeadState) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// ErrBadTransition: the lead cannot make that move from its current state.
var ErrBadTransition = fmt.Errorf("%w: the lead cannot move to that state", shared.ErrConflict)

// Origin is who opened a lead.
type Origin string

const (
	OriginRule    Origin = "rule"
	OriginUser    Origin = "user"
	OriginAIAgent Origin = "ai_agent"
	OriginSystem  Origin = "system"
)

// Likelihood is the opener's band for how likely the step is useful; the
// score's prior. Never a number chosen by the opener.
type Likelihood string

const (
	LikelihoodLow    Likelihood = "low"
	LikelihoodMedium Likelihood = "medium"
	LikelihoodHigh   Likelihood = "high"
)

// Prior is the band's prior probability that a step is useful.
func (l Likelihood) Prior() float64 {
	switch l {
	case LikelihoodLow:
		return 0.1
	case LikelihoodHigh:
		return 0.6
	}
	return 0.3
}

// IsValid reports whether l is a known band.
func (l Likelihood) IsValid() bool {
	return l == LikelihoodLow || l == LikelihoodMedium || l == LikelihoodHigh
}

// Bounds of stored text (the columns' checks).
const (
	MaxRationale  = 2000
	MaxReasonCode = 128
	MaxOriginRef  = 200
	MaxParamsSize = 8192
	MaxBlocked    = 128
)

var keyRe = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// ValidKey reports whether k has the "<word>.<word>" shape of a lead type
// or capability key.
func ValidKey(k string) bool { return len(k) <= 64 && keyRe.MatchString(k) }

// Action is a lead's typed next step: one stage catalog capability with
// its params. It is never a tool command line.
type Action struct {
	Capability string         `json:"capability"`
	Params     map[string]any `json:"params,omitempty"`
}

// Tier is the action's intrusiveness, from the stage catalog (never from
// the opener). ok is false for a capability the catalog does not know.
func (a Action) Tier() (stage.Tier, bool) {
	st, ok := stage.Lookup(stage.Key(a.Capability))
	if !ok {
		return 0, false
	}
	return st.Tier, true
}

// Lead is one question of an exploration.
type Lead struct {
	ID               shared.ID
	TenantID         shared.ID
	ExplorationID    shared.ID
	Type             string
	State            LeadState
	Action           Action
	ActionHash       string
	Tier             stage.Tier
	SubjectAssetID   *shared.ID
	SubjectFindingID *shared.ID
	ReasonCode       string
	Rationale        string
	Origin           Origin
	OriginRef        string
	Likelihood       Likelihood
	Score            float64
	ScoreInputs      map[string]any
	DedupKey         string
	BlockedReason    string
	Attempts         int
	NextAttemptAt    *time.Time
	ApprovedBy       *shared.ID
	ApprovedAt       *time.Time
	CreatedBy        *shared.ID
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ClosedAt         *time.Time
	RowVersion       int
}

// NewLeadInput is what an opener (a rule or a person) supplies. The tier,
// dedup key, action hash and initial state are derived, never supplied.
type NewLeadInput struct {
	TenantID         shared.ID
	ExplorationID    shared.ID
	Type             string
	Action           Action
	SubjectAssetID   *shared.ID
	SubjectFindingID *shared.ID
	ReasonCode       string
	Rationale        string
	Origin           Origin
	OriginRef        string
	Likelihood       Likelihood
	CreatedBy        *shared.ID
	// AutoActive: the tenant's automatic coverage covers active (T1) steps,
	// so an active lead opens without an approval.
	AutoActive bool
}

// NewLead validates the input and builds a lead in its initial state.
func NewLead(in NewLeadInput) (*Lead, error) {
	switch {
	case in.TenantID.IsZero() || in.ExplorationID.IsZero():
		return nil, fmt.Errorf("%w: tenant and exploration are required", shared.ErrValidation)
	case !ValidKey(in.Type):
		return nil, fmt.Errorf("%w: invalid lead type", shared.ErrValidation)
	case !ValidKey(in.Action.Capability):
		return nil, fmt.Errorf("%w: a lead needs a typed action", shared.ErrValidation)
	case (in.SubjectAssetID == nil) == (in.SubjectFindingID == nil):
		return nil, fmt.Errorf("%w: a lead has exactly one subject", shared.ErrValidation)
	case in.ReasonCode == "" || len(in.ReasonCode) > MaxReasonCode:
		return nil, fmt.Errorf("%w: invalid reason code", shared.ErrValidation)
	case utf8.RuneCountInString(in.Rationale) > MaxRationale:
		return nil, fmt.Errorf("%w: rationale is too long", shared.ErrValidation)
	case in.OriginRef == "" || len(in.OriginRef) > MaxOriginRef:
		return nil, fmt.Errorf("%w: invalid origin reference", shared.ErrValidation)
	}
	switch in.Origin {
	case OriginRule, OriginUser, OriginAIAgent, OriginSystem:
	default:
		return nil, fmt.Errorf("%w: invalid origin", shared.ErrValidation)
	}
	if in.Likelihood == "" {
		in.Likelihood = LikelihoodMedium
	}
	if !in.Likelihood.IsValid() {
		return nil, fmt.Errorf("%w: invalid likelihood", shared.ErrValidation)
	}
	tier, ok := in.Action.Tier()
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a capability of the stage catalog", shared.ErrValidation, in.Action.Capability)
	}
	if in.Action.Params == nil {
		in.Action.Params = map[string]any{}
	}
	if b, err := json.Marshal(in.Action.Params); err != nil || len(b) > MaxParamsSize {
		return nil, fmt.Errorf("%w: invalid action params", shared.ErrValidation)
	}
	l := &Lead{
		ID: shared.NewID(), TenantID: in.TenantID, ExplorationID: in.ExplorationID, Type: in.Type,
		Action: in.Action, Tier: tier, SubjectAssetID: in.SubjectAssetID, SubjectFindingID: in.SubjectFindingID,
		ReasonCode: in.ReasonCode, Rationale: strings.TrimSpace(in.Rationale), Origin: in.Origin,
		OriginRef: in.OriginRef, Likelihood: in.Likelihood, CreatedBy: in.CreatedBy,
		ScoreInputs: map[string]any{}, RowVersion: 1,
	}
	l.DedupKey = l.dedupKey()
	l.ActionHash = l.actionHash()
	l.State = InitialState(in.Origin, tier, in.AutoActive)
	return l, nil
}

// InitialState is where a new lead starts (approvals by tier):
//   - an AI agent's lead is only ever proposed; a person accepts it;
//   - passive (T0) opens at once;
//   - active non-intrusive (T1) opens when the tenant's automatic coverage is
//     on, else waits for a person;
//   - intrusive (T2) always waits for a person with step-up, whoever opened it.
func InitialState(origin Origin, tier stage.Tier, autoActive bool) LeadState {
	switch {
	case origin == OriginAIAgent:
		return StateProposed
	case tier >= stage.TierIntrusive:
		return StateAwaitingApproval
	case tier == stage.TierActive && !autoActive:
		return StateAwaitingApproval
	}
	return StateOpen
}

// subjectRef is "asset:<id>" or "finding:<id>".
func (l *Lead) subjectRef() string {
	if l.SubjectAssetID != nil {
		return "asset:" + l.SubjectAssetID.String()
	}
	if l.SubjectFindingID != nil {
		return "finding:" + l.SubjectFindingID.String()
	}
	return ""
}

// dedupKey identifies the question: one live lead per lead type, subject and
// capability in an exploration.
func (l *Lead) dedupKey() string {
	return l.Type + "|" + l.subjectRef() + "|" + l.Action.Capability
}

// actionHash is sha256 over the canonical action (json.Marshal sorts map
// keys) and the subject.
func (l *Lead) actionHash() string {
	b, _ := json.Marshal(struct {
		Type    string         `json:"t"`
		Cap     string         `json:"c"`
		Params  map[string]any `json:"p"`
		Subject string         `json:"s"`
	}{l.Type, l.Action.Capability, l.Action.Params, l.subjectRef()})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Move changes the lead's state when the move is allowed, stamping the close
// time of a closing move.
func (l *Lead) Move(to LeadState, now time.Time) error {
	if !CanMove(l.State, to) {
		return ErrBadTransition
	}
	l.State = to
	l.UpdatedAt = now
	if !to.Live() {
		t := now
		l.ClosedAt = &t
	}
	return nil
}

// LinkRel is what a link says about its lead.
type LinkRel string

const (
	// RelDerivedFrom: the lead exists because of this record.
	RelDerivedFrom LinkRel = "derived_from"
	// RelDispatchedAs: the lead was dispatched as this run.
	RelDispatchedAs LinkRel = "dispatched_as"
	// RelYields: the lead's step produced (or confirmed, or did not find) this.
	RelYields LinkRel = "yields"
)

// EndKind is the type of a link's other end.
type EndKind string

const (
	EndAsset   EndKind = "asset"
	EndFinding EndKind = "finding"
	EndScanRun EndKind = "scan_run"
	EndLead    EndKind = "lead"
)

// Effect is what a step did to the end it yields.
type Effect string

const (
	EffectCreated   Effect = "created"
	EffectChanged   Effect = "changed"
	EffectConfirmed Effect = "confirmed"
	EffectNotFound  Effect = "not_found"
	EffectBlocked   Effect = "blocked"
	EffectFailed    Effect = "failed"
)

// Link is one typed link of a lead. EndID is nil when the record it pointed
// at was removed (the kind stays).
type Link struct {
	ID            int64
	TenantID      shared.ID
	LeadID        shared.ID
	Rel           LinkRel
	EndKind       EndKind
	EndID         *shared.ID
	Effect        Effect
	OutcomeReason string
	CreatedAt     time.Time
}

// Validate checks the link's shape (the columns' checks).
func (k Link) Validate() error {
	switch k.Rel {
	case RelDerivedFrom, RelDispatchedAs, RelYields:
	default:
		return fmt.Errorf("%w: invalid link relation", shared.ErrValidation)
	}
	switch k.EndKind {
	case EndAsset, EndFinding, EndScanRun, EndLead:
	default:
		return fmt.Errorf("%w: invalid link end", shared.ErrValidation)
	}
	if k.EndID == nil || k.LeadID.IsZero() || k.TenantID.IsZero() {
		return fmt.Errorf("%w: a link needs its tenant, lead and end", shared.ErrValidation)
	}
	if k.Rel == RelDispatchedAs && k.EndKind != EndScanRun {
		return fmt.Errorf("%w: a lead is dispatched as a run", shared.ErrValidation)
	}
	if len(k.OutcomeReason) > MaxReasonCode {
		return fmt.Errorf("%w: outcome reason is too long", shared.ErrValidation)
	}
	return nil
}

// VerdictKind is a lead's answer.
type VerdictKind string

const (
	VerdictProven       VerdictKind = "proven"
	VerdictRefuted      VerdictKind = "refuted"
	VerdictInconclusive VerdictKind = "inconclusive"
)

// VerdictTier is how trustworthy the checker is.
type VerdictTier string

const (
	// TierDeterministic: a reproducible check (a scan run's result, a retest).
	TierDeterministic VerdictTier = "deterministic"
	// TierHuman: a person, with evidence.
	TierHuman VerdictTier = "human"
	// TierHeuristic: a rule's inference.
	TierHeuristic VerdictTier = "heuristic"
	// TierAI: an AI agent's view; never proof.
	TierAI VerdictTier = "ai"
)

// EvidenceRef points at stored evidence by reference and hash, never by body.
type EvidenceRef struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	SHA256 string `json:"sha256,omitempty"`
}

// Verdict is one append-only answer to a lead.
type Verdict struct {
	ID        shared.ID
	TenantID  shared.ID
	LeadID    shared.ID
	Verdict   VerdictKind
	Tier      VerdictTier
	Checker   string
	Evidence  []EvidenceRef
	Reason    string
	DecidedBy *shared.ID
	CreatedAt time.Time
}

// Validate enforces the proof wording: proven only from a deterministic
// check or from a person with evidence.
func (v Verdict) Validate() error {
	switch v.Verdict {
	case VerdictProven, VerdictRefuted, VerdictInconclusive:
	default:
		return fmt.Errorf("%w: invalid verdict", shared.ErrValidation)
	}
	switch v.Tier {
	case TierDeterministic, TierHeuristic, TierAI:
	case TierHuman:
		if v.DecidedBy == nil || v.Checker != "user:"+v.DecidedBy.String() {
			return fmt.Errorf("%w: a person's verdict names the person", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: invalid verdict tier", shared.ErrValidation)
	}
	if v.Verdict == VerdictProven {
		if v.Tier != TierDeterministic && v.Tier != TierHuman {
			return fmt.Errorf("%w: only a deterministic check or a person proves a lead", shared.ErrValidation)
		}
		if v.Tier == TierHuman && len(v.Evidence) == 0 {
			return fmt.Errorf("%w: a person proves a lead with evidence", shared.ErrValidation)
		}
	}
	if v.Checker == "" || len(v.Checker) > MaxOriginRef || utf8.RuneCountInString(v.Reason) > MaxRationale {
		return fmt.Errorf("%w: invalid checker or reason", shared.ErrValidation)
	}
	return nil
}

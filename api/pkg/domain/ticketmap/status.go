package ticketmap

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Status categories of a tracker workflow.
const (
	CategoryNew           = "new"           // To Do
	CategoryIndeterminate = "indeterminate" // In Progress
	CategoryDone          = "done"          // Done
)

func validCategory(c string) bool {
	return c == CategoryNew || c == CategoryIndeterminate || c == CategoryDone
}

// OpenCTEM states a status map can move an issue for. Finding states follow
// the finding lifecycle plus the verification events; task states are derived
// from the members (DeriveTaskState).
const (
	// Finding.
	StateNew                = "new"
	StateConfirmed          = "confirmed"
	StateInProgress         = "in_progress"
	StateFixApplied         = "fix_applied"         // fix claimed, verification pending
	StateVerified           = "verified"            // resolved with proof
	StateVerificationFailed = "verification_failed" // the retest or scan still sees it
	StateFalsePositive      = "false_positive"
	StateAccepted           = "accepted"
	StateDuplicate          = "duplicate"
	StateRegressed          = "regressed"          // seen again after verified
	StateAcceptanceExpired  = "acceptance_expired" // accepted risk ran out

	// Task.
	TaskOpen       = "open"
	TaskInProgress = "in_progress"
	TaskFixClaimed = "fix_claimed"
	TaskVerifying  = "verifying"
	TaskDone       = "done"
	TaskBlocked    = "blocked"
	TaskArchived   = "archived"
)

// OutboundStates lists the states a status map may map, per object kind.
func OutboundStates(kind ObjectKind) []string {
	if kind == ObjectTask {
		return []string{TaskOpen, TaskInProgress, TaskFixClaimed, TaskVerifying, TaskDone, TaskBlocked, TaskArchived}
	}
	return []string{
		StateNew, StateConfirmed, StateInProgress, StateFixApplied, StateVerified, StateVerificationFailed,
		StateFalsePositive, StateAccepted, StateDuplicate, StateRegressed, StateAcceptanceExpired,
	}
}

// StatusTarget is where an OpenCTEM state moves the issue: one workflow
// status, plus the values the transition screens need.
type StatusTarget struct {
	StatusID string `json:"status_id" yaml:"status_id"`
	Name     string `json:"name,omitempty" yaml:"name,omitempty"`
	// Resolution is set on the transition that offers a resolution field
	// (e.g. "Done" for verified, "Won't Do" for accepted risk).
	Resolution string `json:"resolution,omitempty" yaml:"resolution,omitempty"`
	// Fields fills other required transition fields: field id → value.
	Fields map[string]string `json:"fields,omitempty" yaml:"fields,omitempty"`
	// Comment posts the platform's explanation with the move.
	Comment bool `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// Intent is what a tracker status means for OpenCTEM. An intent is a request
// to a service path, never a status written directly; none of them closes a
// finding.
type Intent string

const (
	IntentIgnore           Intent = "ignore"
	IntentInProgress       Intent = "in_progress"       // work started
	IntentFixClaim         Intent = "fix_claim"         // fix claimed → verification
	IntentReopen           Intent = "reopen"            // back to work, with a note
	IntentRequestAccept    Intent = "request_accept"    // risk-acceptance request, four-eyes
	IntentRequestFP        Intent = "request_fp"        // false-positive request, four-eyes
	IntentSuggestDuplicate Intent = "suggest_duplicate" // duplicate suggestion for a person
)

// Valid reports whether i is a known intent.
func (i Intent) Valid() bool {
	switch i {
	case IntentIgnore, IntentInProgress, IntentFixClaim, IntentReopen,
		IntentRequestAccept, IntentRequestFP, IntentSuggestDuplicate:
		return true
	}
	return false
}

// NeedsApproval reports whether the intent only opens a request a second
// person decides.
func (i Intent) NeedsApproval() bool {
	return i == IntentRequestAccept || i == IntentRequestFP
}

// InboundRule matches a tracker status (and optionally its resolution) to an
// intent. Rules are evaluated in order; the first match wins. A rule matches
// a status id, or a whole category when StatusID is empty.
type InboundRule struct {
	StatusID   string `json:"status_id,omitempty" yaml:"status_id,omitempty"`
	Category   string `json:"category,omitempty" yaml:"category,omitempty"`
	Resolution string `json:"resolution,omitempty" yaml:"resolution,omitempty"` // "" = any
	Intent     Intent `json:"intent" yaml:"intent"`
}

// Regression policies.
const (
	RegressionNewIssue = "new_issue"
	RegressionReopen   = "reopen"
)

// StatusMap maps OpenCTEM states to workflow statuses and workflow statuses
// back to intents.
type StatusMap struct {
	Outbound map[string]StatusTarget `json:"outbound,omitempty" yaml:"outbound,omitempty"`
	Inbound  []InboundRule           `json:"inbound,omitempty" yaml:"inbound,omitempty"`
	// VerifyingLabel is added while a claimed fix waits for verification
	// (e.g. "openctem:verifying") and removed afterwards.
	VerifyingLabel string `json:"verifying_label,omitempty" yaml:"verifying_label,omitempty"`
	// SLABreachLabel is added when the SLA is breached.
	SLABreachLabel string `json:"sla_breach_label,omitempty" yaml:"sla_breach_label,omitempty"`
	// Regression: reopen the issue or open a new linked one.
	Regression string `json:"regression,omitempty" yaml:"regression,omitempty"`
}

func (m StatusMap) checkShape(kind ObjectKind) error {
	if len(m.Outbound)+len(m.Inbound) > MaxStatusEntries {
		return fmt.Errorf("%w: at most %d status entries", shared.ErrValidation, MaxStatusEntries)
	}
	allowed := make(map[string]bool)
	for _, s := range OutboundStates(kind) {
		allowed[s] = true
	}
	for st, t := range m.Outbound {
		if !allowed[st] {
			return fmt.Errorf("%w: %q is not a %s state", shared.ErrValidation, st, kind)
		}
		if t.StatusID == "" || len(t.StatusID) > 64 || len(t.Resolution) > 128 || len(t.Fields) > 10 {
			return fmt.Errorf("%w: outbound %q needs a workflow status", shared.ErrValidation, st)
		}
		for id, v := range t.Fields {
			if !validFieldID(id) || len(v) > MaxConstRunes {
				return fmt.Errorf("%w: outbound %q: invalid transition field", shared.ErrValidation, st)
			}
		}
	}
	for i, r := range m.Inbound {
		if !r.Intent.Valid() {
			return fmt.Errorf("%w: inbound rule %d: unknown intent %q", shared.ErrValidation, i+1, r.Intent)
		}
		if r.StatusID == "" && !validCategory(r.Category) {
			return fmt.Errorf("%w: inbound rule %d needs a status or a category", shared.ErrValidation, i+1)
		}
		if len(r.StatusID) > 64 || len(r.Resolution) > 128 {
			return fmt.Errorf("%w: inbound rule %d too long", shared.ErrValidation, i+1)
		}
	}
	switch m.Regression {
	case "", RegressionNewIssue, RegressionReopen:
	default:
		return fmt.Errorf("%w: regression must be new_issue or reopen", shared.ErrValidation)
	}
	for _, l := range []string{m.VerifyingLabel, m.SLABreachLabel} {
		if len(l) > 64 || strings.ContainsAny(l, " \t\n") {
			return fmt.Errorf("%w: labels have no spaces and at most 64 characters", shared.ErrValidation)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Workflow graph and transition paths.

// WorkflowStatus is one status of a workflow.
type WorkflowStatus struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// TransitionField is a field on a transition screen.
type TransitionField struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Required      bool           `json:"required"`
	AllowedValues []AllowedValue `json:"allowed_values,omitempty"`
}

// WorkflowTransition is an edge of the workflow. Empty From means a global
// transition (from any status).
type WorkflowTransition struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	From   []string          `json:"from,omitempty"`
	To     string            `json:"to"`
	Fields []TransitionField `json:"fields,omitempty"`
}

// Workflow is a project's workflow for one issue type.
type Workflow struct {
	Statuses    []WorkflowStatus     `json:"statuses"`
	Transitions []WorkflowTransition `json:"transitions"`
	// Resolutions are the values the resolution field allows.
	Resolutions []AllowedValue `json:"resolutions,omitempty"`
}

// Status finds a workflow status by id.
func (w Workflow) Status(id string) (WorkflowStatus, bool) {
	for _, s := range w.Statuses {
		if s.ID == id {
			return s, true
		}
	}
	return WorkflowStatus{}, false
}

func (t WorkflowTransition) from(status string) bool {
	if len(t.From) == 0 {
		return true
	}
	for _, f := range t.From {
		if f == status {
			return true
		}
	}
	return false
}

// MaxPathSteps bounds a transition path.
const MaxPathSteps = 8

// ErrUnreachable: the workflow has no path between two statuses.
var ErrUnreachable = fmt.Errorf("%w: the target status cannot be reached through the workflow", shared.ErrValidation)

// Path finds the shortest transition path from one status to another (BFS
// over the workflow, at most MaxPathSteps). Same status → empty path.
// Unreachable → ErrUnreachable: the engine never guesses a status.
func (w Workflow) Path(from, to string) ([]WorkflowTransition, error) {
	if from == to {
		return nil, nil
	}
	if _, ok := w.Status(to); !ok {
		return nil, fmt.Errorf("%w: status %q is not in the workflow", shared.ErrValidation, to)
	}
	type node struct {
		status string
		path   []WorkflowTransition
	}
	visited := map[string]bool{from: true}
	queue := []node{{status: from}}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if len(n.path) >= MaxPathSteps {
			continue
		}
		for _, t := range w.Transitions {
			if !t.from(n.status) || visited[t.To] {
				continue
			}
			p := make([]WorkflowTransition, len(n.path)+1)
			copy(p, n.path)
			p[len(n.path)] = t
			if t.To == to {
				return p, nil
			}
			visited[t.To] = true
			queue = append(queue, node{status: t.To, path: p})
		}
	}
	return nil, ErrUnreachable
}

// TransitionStep is one transition to execute with its screen values.
type TransitionStep struct {
	TransitionID string            `json:"transition_id"`
	Name         string            `json:"name"`
	To           string            `json:"to"`
	Fields       map[string]string `json:"fields,omitempty"`
}

// ResolutionFieldID is the system resolution field.
const ResolutionFieldID = "resolution"

// Plan turns a path into executable steps, filling every required screen
// field from the target (the resolution field from Resolution, others from
// Fields). A required field with no value is an error, never a guess.
func (w Workflow) Plan(from string, target StatusTarget) ([]TransitionStep, error) {
	path, err := w.Path(from, target.StatusID)
	if err != nil {
		return nil, err
	}
	steps := make([]TransitionStep, 0, len(path))
	for i, t := range path {
		last := i == len(path)-1
		fields := map[string]string{}
		for _, f := range t.Fields {
			v, ok := target.Fields[f.ID]
			if f.ID == ResolutionFieldID && target.Resolution != "" && last {
				v, ok = target.Resolution, true
			}
			if !ok {
				if f.Required {
					return nil, fmt.Errorf("%w: transition %q requires field %q", shared.ErrValidation, t.Name, f.Name)
				}
				continue
			}
			if len(f.AllowedValues) > 0 && !allowedHas(f.AllowedValues, v) {
				return nil, fmt.Errorf("%w: transition %q: %q is not allowed for %q", shared.ErrValidation, t.Name, v, f.Name)
			}
			fields[f.ID] = v
		}
		if len(fields) == 0 {
			fields = nil
		}
		steps = append(steps, TransitionStep{TransitionID: t.ID, Name: t.Name, To: t.To, Fields: fields})
	}
	return steps, nil
}

// ---------------------------------------------------------------------------
// Inbound: status → intent → decision.

// StatusEvent is a status change seen in the tracker.
type StatusEvent struct {
	StatusID   string
	Category   string
	Resolution string
	AuthorID   string    // tracker account that made the change
	At         time.Time // when the tracker recorded it
}

// IntentFor returns the intent of a status event: the first matching rule,
// else ignore with mapped=false (the caller raises a health warning).
func (m StatusMap) IntentFor(ev StatusEvent) (intent Intent, mapped bool) {
	for _, r := range m.Inbound {
		if r.StatusID != "" && r.StatusID != ev.StatusID {
			continue
		}
		if r.StatusID == "" && r.Category != ev.Category {
			continue
		}
		if r.Resolution != "" && !strings.EqualFold(r.Resolution, ev.Resolution) {
			continue
		}
		return r.Intent, true
	}
	return IntentIgnore, false
}

// LastPush is what OpenCTEM last wrote to the issue's status (origin marker).
type LastPush struct {
	StatusID string
	At       time.Time
}

// EchoWindow is how long an inbound status equal to our own last push is
// treated as the echo of that push.
const EchoWindow = 10 * time.Minute

// IsEcho reports whether a status event is the echo of our own transition:
// made by the integration's own account, or the status we pushed within the
// echo window.
func IsEcho(ev StatusEvent, last LastPush, ownAccountID string) bool {
	if ownAccountID != "" && ev.AuthorID == ownAccountID {
		return true
	}
	if last.StatusID == "" || ev.StatusID != last.StatusID {
		return false
	}
	return !ev.At.Before(last.At) && ev.At.Sub(last.At) <= EchoWindow
}

// Decision is what an intent does to a finding in its current state.
type Decision struct {
	Intent Intent `json:"intent"`
	// Command is the service command to run; "" = nothing to do.
	Command string `json:"command"`
	// NeedsApproval: the command only opens a request (four-eyes).
	NeedsApproval bool `json:"needs_approval"`
	// Reason explains a no-op (shown in the simulator and the timeline).
	Reason string `json:"reason,omitempty"`
}

// Service commands an inbound decision can name.
const (
	CmdStartWork        = "start_work"         // → in_progress through the legal path
	CmdClaimFix         = "claim_fix"          // → fix_applied + verification
	CmdReopen           = "reopen"             // fix_applied → in_progress, cancel the queued retest; note
	CmdRequestAccept    = "request_acceptance" // risk-acceptance request
	CmdRequestFP        = "request_fp"         // false-positive request
	CmdSuggestDuplicate = "suggest_duplicate"  // a duplicate suggestion
)

const (
	reasonClosed     = "finding is already closed"
	reasonReopenHere = "finding is closed; reopen it in OpenCTEM"
)

// DecideFinding maps an intent to a command for a finding in status current.
// It is the anti-ping-pong rule set: an issue closed while OpenCTEM still
// verifies keeps the claim; a closed finding is never reopened from the
// tracker except through a person's request.
func DecideFinding(intent Intent, current string) Decision {
	d := Decision{Intent: intent}
	closed := current == "resolved" || current == StateFalsePositive || current == StateAccepted || current == StateDuplicate
	switch intent {
	case IntentIgnore:
		d.Reason = "status not mapped"
	case IntentInProgress:
		switch {
		case current == StateNew || current == StateConfirmed:
			d.Command = CmdStartWork
		case current == StateFixApplied:
			d.Command = CmdReopen
		case closed:
			d.Reason = reasonReopenHere
		default:
			d.Reason = "already in progress"
		}
	case IntentFixClaim:
		switch {
		case current == StateFixApplied:
			d.Reason = "fix already claimed; verification pending"
		case closed:
			d.Reason = reasonClosed
		default:
			d.Command = CmdClaimFix
		}
	case IntentReopen:
		switch {
		case current == StateFixApplied:
			d.Command = CmdReopen
		case closed:
			d.Reason = reasonReopenHere
		default:
			d.Reason = "finding is already open"
		}
	case IntentRequestAccept, IntentRequestFP:
		if closed {
			d.Reason = reasonClosed
			break
		}
		d.NeedsApproval = true
		d.Command = CmdRequestAccept
		if intent == IntentRequestFP {
			d.Command = CmdRequestFP
		}
	case IntentSuggestDuplicate:
		if closed {
			d.Reason = reasonClosed
			break
		}
		d.Command = CmdSuggestDuplicate
	}
	return d
}

// ---------------------------------------------------------------------------
// Task state derived from member states.

// MemberCounts counts a task's members by finding status. Resolved counts
// resolved members, Verified those of them with proof of fix, Closed the
// other closures (false positive, accepted, duplicate).
type MemberCounts struct {
	New, Confirmed, InProgress, FixApplied, Resolved, Verified, Closed int
}

// DeriveTaskState returns the task state from its members (a manual
// blocked/archived flag wins). Done needs every member closed and at least
// one verified fix when any member was resolved.
func DeriveTaskState(c MemberCounts, blocked, archived bool) string {
	switch {
	case archived:
		return TaskArchived
	case blocked:
		return TaskBlocked
	}
	open := c.New + c.Confirmed + c.InProgress + c.FixApplied
	switch {
	case open == 0 && c.Resolved > 0 && c.Verified == 0:
		return TaskVerifying // resolved but no member proven fixed yet
	case open == 0 && c.Resolved+c.Closed > 0:
		return TaskDone
	case open > 0 && c.FixApplied == open:
		return TaskVerifying
	case c.InProgress > 0 || c.FixApplied > 0:
		return TaskInProgress
	}
	return TaskOpen
}

// ProgressNote is the comment a mixed-state task posts with its status.
func ProgressNote(c MemberCounts) string {
	total := c.New + c.Confirmed + c.InProgress + c.FixApplied + c.Resolved + c.Closed
	return fmt.Sprintf("Progress: %d of %d findings verified fixed, %d fix claimed (verifying), %d in progress, %d open.",
		c.Verified, total, c.FixApplied, c.InProgress, c.New+c.Confirmed)
}

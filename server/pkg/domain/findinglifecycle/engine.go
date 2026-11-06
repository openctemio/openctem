package findinglifecycle

import (
	"slices"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The tenant layer of the transition engine. The platform decides first
// (vulnerability.EvaluateTransition, unchanged); the organization's scheme
// can then only add requirements or blocks. It never clears a block, never
// removes a requirement and never makes a request direct. A nil scheme is
// the system lifecycle: exactly the platform's decisions.
//
// Same-status moves (a label change between sub-statuses of one canonical
// status) are not platform moves: they need findings:status (a ticket only
// within the statuses it may report, a workflow as an explicit system move)
// and, under a closed status, a sub-status bound to the finding's own
// closure reason.

// Actor is the platform actor plus the finding permissions it holds, for
// require_permission guards (an owner or admin holds all of them).
type Actor struct {
	vulnerability.TransitionActor
	Permissions []string
}

func (a Actor) holdsAny(perms []string) bool {
	for _, p := range perms {
		if slices.Contains(a.Permissions, p) {
			return true
		}
	}
	return false
}

// Facts are what a decision about one finding reads.
type Facts struct {
	vulnerability.TransitionFacts
	// SubStatus is the finding's sub-status (zero = the default label).
	SubStatus     shared.ID
	ClosureReason vulnerability.ClosureReason
	FindingType   string
	ToolName      string
}

func (f Facts) conditionFacts() ConditionFacts {
	return ConditionFacts{
		Severity: string(f.Severity), PriorityClass: f.PriorityClass, IsKEV: f.IsKEV,
		Source: string(f.Source), FindingType: f.FindingType, ToolName: f.ToolName,
	}
}

// ConditionFacts returns the values context selectors and when conditions read.
func (f Facts) ConditionFacts() ConditionFacts { return f.conditionFacts() }

// Block codes the tenant layer adds.
const (
	// BlockNotInLifecycle: the organization's lifecycle has no such move.
	BlockNotInLifecycle = "not_in_lifecycle"
	// BlockSameSubStatus: the finding already has this sub-status.
	BlockSameSubStatus = "same_sub_status"
	// BlockClosureReasonChange: a closed sub-status bound to another closure
	// reason than the finding's (that is a new decision, not a label).
	BlockClosureReasonChange = "closure_reason_change"
	// BlockPlatformSubStatus: the sub-status is bound to a closure reason
	// only the platform sets (an obsolete asset, source or rule).
	BlockPlatformSubStatus = "platform_sub_status"
	// BlockLifecyclePermission: the move needs one of the permissions in
	// params any_of (comma separated).
	BlockLifecyclePermission = "lifecycle_permission"
	// BlockActorKindDenied: the organization keeps this kind of actor
	// (automation, ticket sync, API key) off the move.
	BlockActorKindDenied = "actor_kind_denied"
)

// Decision is the platform decision narrowed by the organization's scheme.
type Decision struct {
	vulnerability.TransitionDecision
	// ToSubStatus is the sub-status the move lands on (zero = the default label).
	ToSubStatus shared.ID `json:"to_sub_status_id,omitzero"`
	// Transition and Name identify the scheme's move, when one matched.
	Transition string `json:"transition,omitempty"`
	Name       string `json:"name,omitempty"`
	// NoteMinLen is the shortest note the move accepts (0 = the platform rule).
	NoteMinLen int `json:"note_min_len,omitempty"`
	// Fields are the inputs the move requires.
	Fields []RequiredField `json:"fields,omitempty"`
	// ClosureReason is the reason a closed sub-status binds; the move sets it.
	ClosureReason vulnerability.ClosureReason `json:"closure_reason,omitempty"`
}

func (d *Decision) block(code string, params ...string) {
	b := vulnerability.TransitionBlock{Code: code}
	if len(params) > 0 {
		b.Params = map[string]string{}
		for i := 0; i+1 < len(params); i += 2 {
			b.Params[params[i]] = params[i+1]
		}
	}
	d.Blocked = append(d.Blocked, b)
	d.Allowed = false
}

func (d *Decision) require(r vulnerability.TransitionRequirement) {
	if !slices.Contains(d.Requires, r) {
		d.Requires = append(d.Requires, r)
	}
}

// EvaluateMove decides a move of a finding with facts by actor to target
// under scheme c (nil = the system lifecycle).
func EvaluateMove(c *Compiled, f Facts, a Actor, to Target) Decision {
	var d Decision
	if to.Status == f.Status {
		d = labelMove(c, f, a, to)
	} else {
		d = Decision{TransitionDecision: vulnerability.EvaluateTransition(f.TransitionFacts, a.TransitionActor, to.Status)}
	}
	d.To = to.Status
	d.ToSubStatus = to.SubStatus
	if !to.SubStatus.IsZero() {
		ref, ok := c.subStatus(to.SubStatus)
		if !ok || ref.Status != to.Status {
			d.block(BlockNotInLifecycle)
			return d
		}
		if ref.ClosureReason != "" {
			d.ClosureReason = ref.ClosureReason
			if to.Status != f.Status && !slices.Contains(vulnerability.PersonClosureReasons(to.Status), ref.ClosureReason) {
				d.block(BlockPlatformSubStatus)
			}
			if to.Status == f.Status && f.ClosureReason != ref.ClosureReason {
				d.block(BlockClosureReasonChange, "from", string(f.ClosureReason), "to", string(ref.ClosureReason))
			}
		}
	}
	if c == nil {
		return d
	}
	c.applyTenantLayer(&d, f, a, to)
	return d
}

// labelMove is the platform part of a same-status move.
func labelMove(c *Compiled, f Facts, a Actor, to Target) Decision {
	d := Decision{TransitionDecision: vulnerability.TransitionDecision{To: to.Status, Allowed: true, Mode: vulnerability.TransitionDirect}}
	if f.Source == vulnerability.FindingSourcePentest {
		d.block(vulnerability.BlockPentestModule)
		return d
	}
	if c == nil {
		// The system lifecycle has no sub-statuses: re-setting a status is
		// what the platform says it is.
		d.TransitionDecision = vulnerability.EvaluateTransition(f.TransitionFacts, a.TransitionActor, to.Status)
		return d
	}
	if to.SubStatus == f.SubStatus {
		d.block(BlockSameSubStatus)
	}
	switch a.Kind {
	case vulnerability.TransitionActorTicket:
		if !to.Status.IsTicketInboundTarget() {
			d.block(vulnerability.BlockTicketCannotClose)
		}
	case vulnerability.TransitionActorWorkflow:
	default:
		if !a.CanStatus {
			d.block(vulnerability.BlockMissingPermission, "permission", "findings:status")
		}
	}
	return d
}

func (c *Compiled) subStatus(id shared.ID) (SubStatusRef, bool) {
	if c == nil {
		return SubStatusRef{}, false
	}
	r, ok := c.subs[id]
	return r, ok
}

// applyTenantLayer narrows d by the scheme's moves from the finding's place
// to target. A move to a specific sub-status, and any move under
// listed_only, needs a listed transition; under canonical_plus_listed a
// canonical move to the target's default label stays available.
func (c *Compiled) applyTenantLayer(d *Decision, f Facts, a Actor, to Target) {
	matched := c.matching(f, to)
	if len(matched) == 0 {
		canonicalDefault := to.Status != f.Status && to.SubStatus.IsZero()
		labelReset := to.Status == f.Status && to.SubStatus.IsZero()
		if c.mode == PersonMovesListedOnly || !(canonicalDefault || labelReset) {
			d.block(BlockNotInLifecycle)
		}
		return
	}
	d.Transition, d.Name = matched[0].id, matched[0].name
	cf := f.conditionFacts()
	for _, t := range matched {
		if !matchAll(t.when, cf) {
			continue
		}
		g := t.guards
		if g.noteMin > 0 {
			d.NoteMinLen = max(d.NoteMinLen, g.noteMin)
			d.require(vulnerability.RequireNote)
		}
		for _, field := range g.fields {
			if !slices.Contains(d.Fields, field) {
				d.Fields = append(d.Fields, field)
			}
		}
		for _, set := range g.anyOf {
			if !a.holdsAny(set) {
				d.block(BlockLifecyclePermission, "any_of", strings.Join(set, ","))
			}
		}
		if slices.Contains(g.denyKinds, a.Kind) {
			d.block(BlockActorKindDenied, "kind", string(a.Kind))
		}
	}
}

// matching returns the scheme's transitions from the finding's place to
// target, in spec order.
func (c *Compiled) matching(f Facts, to Target) []compiledTransition {
	var out []compiledTransition
	for _, t := range c.transitions {
		if t.to == to && t.matchesFrom(f.Status, f.SubStatus) {
			out = append(out, t)
		}
	}
	return out
}

// AvailableMoves returns a decision for every move offered from the
// finding's place: the canonical moves (to each target's default label,
// unless the scheme is listed_only) and the scheme's listed moves, allowed
// or not, with the reasons. A pentest finding has none here.
func AvailableMoves(c *Compiled, f Facts, a Actor) []Decision {
	if f.Source == vulnerability.FindingSourcePentest {
		return []Decision{}
	}
	out := []Decision{}
	seen := map[Target]bool{}
	add := func(t Target) {
		if seen[t] {
			return
		}
		seen[t] = true
		out = append(out, EvaluateMove(c, f, a, t))
	}
	for _, st := range vulnerability.ValidStatusTransitions[f.Status] {
		t := Target{Status: st}
		if c != nil && c.mode == PersonMovesListedOnly && len(c.matching(f, t)) == 0 {
			continue
		}
		add(t)
	}
	if c == nil {
		return out
	}
	for _, t := range c.transitions {
		if t.matchesFrom(f.Status, f.SubStatus) {
			if t.to.Status == f.Status && t.to.SubStatus == f.SubStatus {
				continue
			}
			add(t.to)
		}
	}
	return out
}

// Selector is a compiled context selector: every condition must match.
type Selector struct {
	conds []compiledCondition
}

// Matches reports whether a finding with facts is in the selector's context.
func (s Selector) Matches(f ConditionFacts) bool {
	return len(s.conds) > 0 && matchAll(s.conds, f)
}

// CompileContext checks a context scheme's selector: 1 to MaxConditions
// conditions from the condition catalog.
func CompileContext(cs []Condition) (Selector, Validation) {
	var v Validation
	if len(cs) == 0 {
		v.errorf(IssueInvalidCondition, "context", "a context scheme names at least one condition")
		return Selector{}, v
	}
	if len(cs) > MaxConditions {
		v.errorf(IssueInvalidCondition, "context", "at most %d conditions", MaxConditions)
		return Selector{}, v
	}
	var sel Selector
	for i, c := range cs {
		cc, err := compileCondition(c)
		if err != nil {
			v.errorf(IssueInvalidCondition, "context["+strconv.Itoa(i)+"]", "%s", err.Error())
			continue
		}
		sel.conds = append(sel.conds, cc)
	}
	return sel, v
}

// Candidate is a published scheme an organization may apply to a finding:
// its compiled form, its context selector (Default = no selector) and its
// priority (lower first).
type Candidate struct {
	Scheme   *Compiled
	Context  Selector
	Priority int
	Default  bool
}

// SelectScheme returns the scheme that applies to a finding: the first
// context scheme (by priority) whose selector matches, else the default
// scheme, else nil (the system lifecycle).
func SelectScheme(cands []Candidate, f ConditionFacts) *Compiled {
	ordered := slices.Clone(cands)
	slices.SortStableFunc(ordered, func(a, b Candidate) int { return a.Priority - b.Priority })
	var def *Compiled
	for _, c := range ordered {
		if c.Default {
			if def == nil {
				def = c.Scheme
			}
			continue
		}
		if c.Context.Matches(f) {
			return c.Scheme
		}
	}
	return def
}

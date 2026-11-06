package findinglifecycle

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// SubStatusRef is what the compiler and the engine need to know about a
// catalog entry.
type SubStatusRef struct {
	ID            shared.ID
	Key           string
	Status        vulnerability.FindingStatus
	ClosureReason vulnerability.ClosureReason
	Archived      bool
}

// Target is where a move goes: a canonical status and, optionally, one of
// its sub-statuses (zero = the status's default label).
type Target struct {
	Status    vulnerability.FindingStatus `json:"status"`
	SubStatus shared.ID                   `json:"sub_status_id,omitzero"`
}

// Meta identifies the version a compiled scheme came from; it is recorded on
// the timeline rows it decides.
type Meta struct {
	SchemeID  shared.ID
	VersionID shared.ID
	Version   int
}

// Compiled is a validated scheme the engine evaluates. It is immutable and
// safe to share between requests (cache it per version id).
type Compiled struct {
	meta        Meta
	mode        PersonMoves
	subs        map[shared.ID]SubStatusRef
	defaults    map[vulnerability.FindingStatus]shared.ID
	transitions []compiledTransition
}

type compiledTransition struct {
	id           string
	name         string
	labels       map[string]string
	fromSubs     []shared.ID
	fromStatuses []vulnerability.FindingStatus
	to           Target
	when         []compiledCondition
	guards       compiledGuards
}

type compiledGuards struct {
	noteMin   int
	fields    []RequiredField
	anyOf     [][]string
	denyKinds []vulnerability.TransitionActorKind
}

// Meta returns the version the scheme was compiled from.
func (c *Compiled) Meta() Meta { return c.meta }

// Mode returns the scheme's person-moves mode.
func (c *Compiled) Mode() PersonMoves { return c.mode }

// Default returns the default sub-status of a status (zero when none).
func (c *Compiled) Default(s vulnerability.FindingStatus) shared.ID { return c.defaults[s] }

// SubStatus returns a sub-status the scheme uses.
func (c *Compiled) SubStatus(id shared.ID) (SubStatusRef, bool) {
	r, ok := c.subs[id]
	return r, ok
}

// Issue is one validation finding about a spec. Code is stable (the web
// console translates it); Path points into the spec; Message is English for
// API clients and logs.
type Issue struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// Validation is the result of compiling a spec.
type Validation struct {
	Errors   []Issue `json:"errors"`
	Warnings []Issue `json:"warnings"`
}

// OK reports whether the spec has no errors.
func (v Validation) OK() bool { return len(v.Errors) == 0 }

// Err returns a validation error naming the first issue, or nil.
func (v Validation) Err() error {
	if v.OK() {
		return nil
	}
	return fmt.Errorf("%w: the lifecycle is not valid: %s (%s)", shared.ErrValidation, v.Errors[0].Message, v.Errors[0].Path)
}

func (v *Validation) errorf(code, path, format string, args ...any) {
	v.Errors = append(v.Errors, Issue{Code: code, Path: path, Message: fmt.Sprintf(format, args...)})
}

func (v *Validation) warnf(code, path, format string, args ...any) {
	v.Warnings = append(v.Warnings, Issue{Code: code, Path: path, Message: fmt.Sprintf(format, args...)})
}

// Validation issue codes.
const (
	IssueInvalidMode         = "invalid_person_moves"
	IssueTooMany             = "too_many"
	IssueUnknownSubStatus    = "unknown_sub_status"
	IssueArchivedSubStatus   = "archived_sub_status"
	IssueInvalidDefault      = "invalid_default"
	IssueInvalidTransition   = "invalid_transition"
	IssueDuplicateTransition = "duplicate_transition"
	IssueInvalidRef          = "invalid_reference"
	IssueForbiddenEdge       = "canonical_forbidden_edge"
	IssueClosureReasonChange = "closure_reason_change"
	IssueInvalidGuard        = "invalid_guard"
	IssueInvalidCondition    = "invalid_condition"
	IssueUnreachable         = "unreachable_closed_status"
	IssueDuplicateUnreached  = "duplicate_unreachable"
)

// Compile validates spec against the organization's catalog and returns the
// compiled scheme. The scheme is usable only when the validation has no
// errors (Compile returns nil then).
func Compile(spec Spec, catalog []SubStatusRef, meta Meta) (*Compiled, Validation) {
	var v Validation
	c := &Compiled{
		meta: meta, mode: spec.PersonMoves,
		subs:     map[shared.ID]SubStatusRef{},
		defaults: map[vulnerability.FindingStatus]shared.ID{},
	}
	if c.mode == "" {
		c.mode = PersonMovesCanonicalPlusListed
	}
	if c.mode != PersonMovesCanonicalPlusListed && c.mode != PersonMovesListedOnly {
		v.errorf(IssueInvalidMode, "person_moves", "person_moves must be canonical_plus_listed or listed_only")
	}

	byID := make(map[shared.ID]SubStatusRef, len(catalog))
	for _, r := range catalog {
		byID[r.ID] = r
	}
	if len(spec.SubStatuses) > MaxSubStatusesPerKind {
		v.errorf(IssueTooMany, "sub_statuses", "at most %d sub-statuses", MaxSubStatusesPerKind)
	}
	for i, raw := range spec.SubStatuses {
		path := fmt.Sprintf("sub_statuses[%d]", i)
		id, err := shared.IDFromString(raw)
		if err != nil {
			v.errorf(IssueUnknownSubStatus, path, "%q is not a sub-status id", truncate(raw))
			continue
		}
		ref, ok := byID[id]
		switch {
		case !ok:
			v.errorf(IssueUnknownSubStatus, path, "sub-status %s is not in the catalog", id)
		case ref.Archived:
			v.errorf(IssueArchivedSubStatus, path, "sub-status %q is archived", ref.Key)
		default:
			c.subs[id] = ref
		}
	}

	compileDefaults(spec, c, &v)

	if len(spec.Transitions) > MaxTransitions {
		v.errorf(IssueTooMany, "transitions", "at most %d transitions", MaxTransitions)
	}
	seen := map[string]bool{}
	for i, ts := range spec.Transitions {
		if i >= MaxTransitions {
			break
		}
		t, ok := compileTransition(ts, fmt.Sprintf("transitions[%d]", i), c, &v)
		if !ok {
			continue
		}
		if seen[t.id] {
			v.errorf(IssueDuplicateTransition, fmt.Sprintf("transitions[%d].id", i), "transition id %q is used twice", t.id)
			continue
		}
		seen[t.id] = true
		c.transitions = append(c.transitions, t)
	}

	if c.mode == PersonMovesListedOnly && v.OK() {
		checkReachability(c, &v)
	}
	if !v.OK() {
		return nil, v
	}
	return c, v
}

func compileDefaults(spec Spec, c *Compiled, v *Validation) {
	for status, raw := range spec.Defaults {
		path := "defaults." + truncate(status)
		st := vulnerability.FindingStatus(status)
		if !IsCanonical(st) {
			v.errorf(IssueInvalidDefault, path, "%q is not a canonical status", truncate(status))
			continue
		}
		id, err := shared.IDFromString(raw)
		if err != nil {
			v.errorf(IssueInvalidDefault, path, "the default of %s is not a sub-status id", st)
			continue
		}
		ref, ok := c.subs[id]
		if !ok {
			v.errorf(IssueInvalidDefault, path, "the default of %s is not one of the scheme's sub-statuses", st)
			continue
		}
		if ref.Status != st {
			v.errorf(IssueInvalidDefault, path, "the default of %s is a sub-status of %s", st, ref.Status)
			continue
		}
		c.defaults[st] = id
	}
}

// parseRef reads a from / to reference: a scheme sub-status id or
// "status:<canonical>".
func parseRef(raw string, c *Compiled) (Target, bool) {
	if s, ok := strings.CutPrefix(raw, statusRefPrefix); ok {
		st := vulnerability.FindingStatus(s)
		if !IsCanonical(st) {
			return Target{}, false
		}
		return Target{Status: st}, true
	}
	id, err := shared.IDFromString(raw)
	if err != nil {
		return Target{}, false
	}
	ref, ok := c.subs[id]
	if !ok {
		return Target{}, false
	}
	return Target{Status: ref.Status, SubStatus: id}, true
}

func compileTransition(ts TransitionSpec, path string, c *Compiled, v *Validation) (compiledTransition, bool) {
	start := len(v.Errors)
	t := compiledTransition{id: strings.TrimSpace(ts.ID)}
	if !keyPattern.MatchString(t.id) {
		v.errorf(IssueInvalidTransition, path+".id", "a transition id is 2-40 lowercase letters, digits or underscores")
	}
	name, err := plainText("name", ts.Name, MaxNameLen, true)
	if err != nil {
		v.errorf(IssueInvalidTransition, path+".name", "%s", errText(err))
	}
	t.name = name
	if len(ts.Labels) > MaxLabels {
		v.errorf(IssueInvalidTransition, path+".labels", "at most %d labels", MaxLabels)
	}
	t.labels = make(map[string]string, len(ts.Labels))
	for lang, label := range ts.Labels {
		l, err := plainText("label", label, MaxNameLen, true)
		if err != nil || !languagePattern.MatchString(lang) {
			v.errorf(IssueInvalidTransition, path+".labels", "labels map a language code to a plain-text name")
			continue
		}
		t.labels[lang] = l
	}

	to, ok := parseRef(strings.TrimSpace(ts.To), c)
	if !ok {
		v.errorf(IssueInvalidRef, path+".to", "to must be one of the scheme's sub-statuses or status:<canonical status>")
	}
	t.to = to
	if len(ts.From) == 0 || len(ts.From) > MaxFromPerTransition {
		v.errorf(IssueInvalidTransition, path+".from", "from lists 1-%d sub-statuses or statuses", MaxFromPerTransition)
	}
	for j, raw := range ts.From {
		if j >= MaxFromPerTransition {
			break
		}
		fpath := fmt.Sprintf("%s.from[%d]", path, j)
		from, ok := parseRef(strings.TrimSpace(raw), c)
		if !ok {
			v.errorf(IssueInvalidRef, fpath, "from entries are the scheme's sub-statuses or status:<canonical status>")
			continue
		}
		if to.Status != "" {
			checkEdge(from, to, fpath, c, v)
		}
		if from.SubStatus.IsZero() {
			if !slices.Contains(t.fromStatuses, from.Status) {
				t.fromStatuses = append(t.fromStatuses, from.Status)
			}
		} else if !slices.Contains(t.fromSubs, from.SubStatus) {
			t.fromSubs = append(t.fromSubs, from.SubStatus)
		}
	}

	if len(ts.When) > MaxConditions {
		v.errorf(IssueInvalidCondition, path+".when", "at most %d conditions", MaxConditions)
	}
	for j, cond := range ts.When {
		if j >= MaxConditions {
			break
		}
		cc, err := compileCondition(cond)
		if err != nil {
			v.errorf(IssueInvalidCondition, fmt.Sprintf("%s.when[%d]", path, j), "%s", err.Error())
			continue
		}
		t.when = append(t.when, cc)
	}

	t.guards = compileGuards(ts.Guards, path, v)
	return t, len(v.Errors) == start
}

// checkEdge refuses a move the canonical lifecycle does not have, and a
// label move between two closed sub-statuses with different closure reasons
// (a change of closure reason is a decision, not a label).
func checkEdge(from, to Target, path string, c *Compiled, v *Validation) {
	if from.Status != to.Status {
		if !from.Status.CanTransitionTo(to.Status) {
			v.errorf(IssueForbiddenEdge, path, "the lifecycle has no move from %s to %s", from.Status, to.Status)
		}
		return
	}
	if !from.SubStatus.IsZero() && from.SubStatus == to.SubStatus {
		v.errorf(IssueInvalidTransition, path, "a transition cannot go from a sub-status to itself")
		return
	}
	if from.SubStatus.IsZero() || to.SubStatus.IsZero() {
		return
	}
	fr, tr := c.subs[from.SubStatus], c.subs[to.SubStatus]
	if fr.ClosureReason != tr.ClosureReason {
		v.errorf(IssueClosureReasonChange, path, "%q and %q have different closure reasons; changing the reason is a new decision, not a label", fr.Key, tr.Key)
	}
}

func compileGuards(gs []Guard, path string, v *Validation) compiledGuards {
	var out compiledGuards
	if len(gs) > MaxGuardsPerMove {
		v.errorf(IssueInvalidGuard, path+".guards", "at most %d guards", MaxGuardsPerMove)
	}
	for j, g := range gs {
		if j >= MaxGuardsPerMove {
			break
		}
		gpath := fmt.Sprintf("%s.guards[%d]", path, j)
		switch g.Kind {
		case GuardRequireNote:
			if g.MinLen < 1 || g.MinLen > MaxRequiredNoteLength {
				v.errorf(IssueInvalidGuard, gpath, "require_note takes min_len 1-%d", MaxRequiredNoteLength)
				continue
			}
			out.noteMin = max(out.noteMin, g.MinLen)
		case GuardRequireFields:
			out.fields = compileFields(g.Fields, out.fields, gpath, v)
		case GuardRequirePermission:
			if set := compilePermissions(g.AnyOf, gpath, v); len(set) > 0 {
				out.anyOf = append(out.anyOf, set)
			}
		case GuardDenyActorKinds:
			out.denyKinds = compileDenyKinds(g.Kinds, out.denyKinds, gpath, v)
		default:
			v.errorf(IssueInvalidGuard, gpath, "unknown guard %q", truncate(string(g.Kind)))
		}
	}
	return out
}

func compileFields(fields []string, acc []RequiredField, path string, v *Validation) []RequiredField {
	if len(fields) == 0 {
		v.errorf(IssueInvalidGuard, path, "require_fields names at least one field")
		return acc
	}
	for _, f := range fields {
		rf := RequiredField(f)
		if !slices.Contains(RequiredFields(), rf) {
			v.errorf(IssueInvalidGuard, path, "%q is not a field a move can require", truncate(f))
			continue
		}
		if !slices.Contains(acc, rf) {
			acc = append(acc, rf)
		}
	}
	return acc
}

func compilePermissions(anyOf []string, path string, v *Validation) []string {
	if len(anyOf) == 0 || len(anyOf) > MaxListValues {
		v.errorf(IssueInvalidGuard, path, "require_permission names 1-%d permissions", MaxListValues)
		return nil
	}
	set := make([]string, 0, len(anyOf))
	for _, p := range anyOf {
		if !slices.Contains(GuardPermissions(), p) {
			v.errorf(IssueInvalidGuard, path, "%q is not a finding permission", truncate(p))
			continue
		}
		set = append(set, p)
	}
	return set
}

func compileDenyKinds(kinds []string, acc []vulnerability.TransitionActorKind, path string, v *Validation) []vulnerability.TransitionActorKind {
	if len(kinds) == 0 {
		v.errorf(IssueInvalidGuard, path, "deny_actor_kinds names at least one actor kind")
		return acc
	}
	for _, k := range kinds {
		ak := vulnerability.TransitionActorKind(k)
		if !slices.Contains(DeniableActorKinds(), ak) {
			v.errorf(IssueInvalidGuard, path, "%q is not an actor kind a move can deny (workflow, ticket_inbound, api_key)", truncate(k))
			continue
		}
		if !slices.Contains(acc, ak) {
			acc = append(acc, ak)
		}
	}
	return acc
}

// node is a place a finding can be in under a scheme: a canonical status
// and one of its sub-statuses (zero = the default label).
type node struct {
	status vulnerability.FindingStatus
	sub    shared.ID
}

// checkReachability: with listed_only a person can make only the listed
// moves, so every open place must still lead to every closed status a
// person decides (resolved, false positive, accepted); a duplicate that
// cannot be reached is only a warning. Guards are ignored here: some role
// can always satisfy them.
func checkReachability(c *Compiled, v *Validation) {
	nodes := []node{}
	for _, st := range CanonicalStatuses() {
		nodes = append(nodes, node{status: st})
	}
	for id, r := range c.subs {
		nodes = append(nodes, node{status: r.Status, sub: id})
	}
	next := func(n node) []node {
		var out []node
		for _, t := range c.transitions {
			if t.matchesFrom(n.status, n.sub) {
				out = append(out, node{status: t.to.Status, sub: t.to.SubStatus})
			}
		}
		return out
	}
	required := []vulnerability.FindingStatus{
		vulnerability.FindingStatusResolved, vulnerability.FindingStatusFalsePositive, vulnerability.FindingStatusAccepted,
	}
	slices.SortFunc(nodes, func(a, b node) int {
		if c := strings.Compare(string(a.status), string(b.status)); c != 0 {
			return c
		}
		return strings.Compare(a.sub.String(), b.sub.String())
	})
	for _, start := range nodes {
		if start.status.IsClosed() {
			continue
		}
		reached := map[vulnerability.FindingStatus]bool{}
		seen := map[node]bool{start: true}
		queue := []node{start}
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			reached[n.status] = true
			for _, m := range next(n) {
				if !seen[m] {
					seen[m] = true
					queue = append(queue, m)
				}
			}
		}
		label := string(start.status)
		if !start.sub.IsZero() {
			label = c.subs[start.sub].Key
		}
		for _, want := range required {
			if !reached[want] {
				v.errorf(IssueUnreachable, "transitions", "with listed_only, %q can never reach %s", label, want)
			}
		}
		if !reached[vulnerability.FindingStatusDuplicate] {
			v.warnf(IssueDuplicateUnreached, "transitions", "with listed_only, %q can never be marked a duplicate", label)
		}
	}
}

// matchesFrom reports whether a finding at (status, sub) is in the
// transition's from set.
func (t compiledTransition) matchesFrom(status vulnerability.FindingStatus, sub shared.ID) bool {
	if slices.Contains(t.fromStatuses, status) {
		return true
	}
	return !sub.IsZero() && slices.Contains(t.fromSubs, sub)
}

func truncate(s string) string {
	const n = 64
	if utf8.RuneCountInString(s) <= n {
		return strings.Map(printable, s)
	}
	return strings.Map(printable, string([]rune(s)[:n])) + "…"
}

func printable(r rune) rune {
	if unicode.IsControl(r) {
		return -1
	}
	return r
}

// errText strips the error kind prefix from a validation error.
func errText(err error) string {
	return strings.TrimPrefix(err.Error(), shared.ErrValidation.Error()+": ")
}

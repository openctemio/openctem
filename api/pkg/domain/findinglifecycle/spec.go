package findinglifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A lifecycle scheme spec, as an organization writes it. It is compiled
// (Compile) against the organization's sub-status catalog before anything
// uses it; the compiled form is what the engine evaluates.

// PersonMoves says which moves a person is offered.
type PersonMoves string

const (
	// PersonMovesCanonicalPlusListed keeps every canonical move (landing on
	// the target's default sub-status) and adds the listed ones. The default.
	PersonMovesCanonicalPlusListed PersonMoves = "canonical_plus_listed"
	// PersonMovesListedOnly offers only the listed moves.
	PersonMovesListedOnly PersonMoves = "listed_only"
)

// Spec limits.
const (
	MaxSpecBytes          = 64 << 10
	MaxTransitions        = 60
	MaxGuardsPerMove      = 8
	MaxConditions         = 8
	MaxListValues         = 50
	MaxFromPerTransition  = 30
	MaxSchemesPerKind     = 10
	MaxRequiredNoteLength = 500
)

// statusRefPrefix names a whole canonical status in from / to: "status:in_progress".
const statusRefPrefix = "status:"

// Spec is a lifecycle scheme as stored in a version.
type Spec struct {
	// SubStatuses are the catalog entries (ids) this scheme uses.
	SubStatuses []string `json:"sub_statuses"`
	// Defaults maps a canonical status to the sub-status (id) a finding in
	// that status shows when it carries none.
	Defaults    map[string]string `json:"defaults,omitempty"`
	PersonMoves PersonMoves       `json:"person_moves,omitempty"`
	Transitions []TransitionSpec  `json:"transitions"`
}

// TransitionSpec is one move of a scheme.
type TransitionSpec struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	// From lists sub-status ids and whole canonical statuses ("status:x").
	From []string `json:"from"`
	// To is a sub-status id or a whole canonical status ("status:x").
	To string `json:"to"`
	// When decides whether the guards apply: every condition must match.
	When   []Condition `json:"when,omitempty"`
	Guards []Guard     `json:"guards,omitempty"`
}

// GuardKind is a constraint a move adds.
type GuardKind string

const (
	// GuardRequireNote: a note of at least MinLen characters.
	GuardRequireNote GuardKind = "require_note"
	// GuardRequireFields: inputs from the closed field catalog.
	GuardRequireFields GuardKind = "require_fields"
	// GuardRequirePermission: the actor holds one of AnyOf.
	GuardRequirePermission GuardKind = "require_permission"
	// GuardDenyActorKinds: these delegated actors may not make the move.
	GuardDenyActorKinds GuardKind = "deny_actor_kinds"
)

// Guard is one constraint; the fields used depend on Kind.
type Guard struct {
	Kind   GuardKind `json:"kind"`
	MinLen int       `json:"min_len,omitempty"`
	Fields []string  `json:"fields,omitempty"`
	AnyOf  []string  `json:"any_of,omitempty"`
	Kinds  []string  `json:"kinds,omitempty"`
}

// RequiredField is an input a move may require. The values travel with the
// move and are kept on the finding's timeline.
type RequiredField string

const (
	FieldTicketLink          RequiredField = "ticket_link"
	FieldFixReference        RequiredField = "fix_reference"
	FieldChangeID            RequiredField = "change_id"
	FieldTargetVersion       RequiredField = "target_version"
	FieldDueDate             RequiredField = "due_date"
	FieldCompensatingControl RequiredField = "compensating_control"
)

// RequiredFields is the closed catalog of required fields.
func RequiredFields() []RequiredField {
	return []RequiredField{
		FieldTicketLink, FieldFixReference, FieldChangeID, FieldTargetVersion, FieldDueDate, FieldCompensatingControl,
	}
}

// GuardPermissions are the permissions require_permission may name: the
// finding permissions a role can hold.
func GuardPermissions() []string {
	return []string{
		"findings:status", "findings:verify", "findings:fix_apply", "findings:triage",
		"findings:write", "findings:approve", "findings:assign",
	}
}

// DeniableActorKinds are the delegated actors deny_actor_kinds may name. A
// person can always be offered a move (the other guards narrow who).
func DeniableActorKinds() []vulnerability.TransitionActorKind {
	return []vulnerability.TransitionActorKind{
		vulnerability.TransitionActorWorkflow, vulnerability.TransitionActorTicket, vulnerability.TransitionActorAPIKey,
	}
}

// ParseSpec decodes a stored or submitted spec strictly: unknown fields and
// trailing data are refused, and so is a spec over MaxSpecBytes.
func ParseSpec(raw []byte) (Spec, error) {
	var s Spec
	if len(raw) > MaxSpecBytes {
		return s, fmt.Errorf("%w: the lifecycle spec is larger than %d bytes", shared.ErrValidation, MaxSpecBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("%w: the lifecycle spec is not valid: %s", shared.ErrValidation, jsonErrorText(err))
	}
	if dec.More() {
		return Spec{}, fmt.Errorf("%w: the lifecycle spec has trailing data", shared.ErrValidation)
	}
	return s, nil
}

// jsonErrorText is the decoder's message without the Go type names it may
// carry.
func jsonErrorText(err error) string {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return fmt.Sprintf("field %q has the wrong type", ute.Field)
	}
	return err.Error()
}

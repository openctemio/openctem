package command

// Idempotent command transitions for sensor protocol v2 (RFC-029 §4.4,
// docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md).
//
// A transition repeated by the sensor that made it, with the same body,
// answers the current command as a replay and has no side effects. Anything
// else delegates to Acknowledge/Start/Complete/Fail, so the state rules and
// the atomic claim stay in one place and protocol v1 keeps its behavior.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Transition is one command state change a sensor requests.
type Transition string

// The v2 transitions.
const (
	TransitionClaim    Transition = "claim"
	TransitionStart    Transition = "start"
	TransitionComplete Transition = "complete"
	TransitionFail     Transition = "fail"
)

// target is the state a transition leads to.
func (t Transition) target() commanddom.CommandStatus {
	switch t {
	case TransitionClaim:
		return commanddom.CommandStatusAcknowledged
	case TransitionStart:
		return commanddom.CommandStatusRunning
	case TransitionComplete:
		return commanddom.CommandStatusCompleted
	case TransitionFail:
		return commanddom.CommandStatusFailed
	}
	return ""
}

// TransitionInput is one transition request.
type TransitionInput struct {
	TenantID     string
	SensorID     string
	CommandID    string
	Result       json.RawMessage // complete
	ErrorMessage string          // fail
	// Refusal is the structured policy refusal of a fail (v2), or nil.
	Refusal *sensordom.DispatchRefusal
	// LeaseEpoch is the lease epoch the sensor holds the command under, when
	// it says (complete, fail): a command claimed again since is refused.
	LeaseEpoch *int
}

// TransitionResult is the command after the transition. Replayed is true when
// the command was already in the requested state by this sensor with the
// same body: nothing changed and no side effect may run.
type TransitionResult struct {
	Command  *commanddom.Command
	Replayed bool
}

// InvalidTransitionError: the command's state does not allow the transition.
// State is the current state ("expired" for a pending command past its
// expiry), so the sensor can drop a finished command.
type InvalidTransitionError struct{ State string }

func (e *InvalidTransitionError) Error() string {
	return fmt.Sprintf("command is %s; the transition is not allowed", e.State)
}

// ErrCommandClaimed: another sensor won the claim of an unassigned command.
var ErrCommandClaimed = errors.New("command already claimed by another sensor")

// ErrTransitionConflict: the command already reached the requested state with
// a different result or message.
var ErrTransitionConflict = errors.New("command already in this state with a different body")

// Transition applies t idempotently. Errors: shared.ErrNotFound (unknown
// command or another sensor's), *InvalidTransitionError, ErrCommandClaimed,
// ErrTransitionConflict, or an infrastructure error.
func (s *Service) Transition(ctx context.Context, t Transition, in TransitionInput) (*TransitionResult, error) {
	if t.target() == "" {
		return nil, fmt.Errorf("%w: unknown transition", shared.ErrValidation)
	}
	cmd, err := s.Get(ctx, in.TenantID, in.CommandID)
	if err != nil {
		return nil, err
	}
	if err := ensureSensorOwnsCommand(cmd, in.SensorID); err != nil {
		return nil, err
	}

	mine := cmd.SensorID != nil && cmd.SensorID.String() == in.SensorID
	if mine && cmd.Status == t.target() {
		if !sameTransitionBody(t, cmd, in) {
			return nil, ErrTransitionConflict
		}
		if t == TransitionClaim && s.jobs != nil {
			// The repeat of a claim is handed out signed too. The sensor
			// already holds the command, so a refusal leaves it as it is
			// (its lease runs out unless the sensor goes on).
			signed, err := s.signJob(ctx, in.SensorID, cmd)
			if err != nil {
				return nil, err
			}
			cmd = signed
		}
		return &TransitionResult{Command: cmd, Replayed: true}, nil
	}
	if !transitionAllowed(t, cmd, mine) {
		return nil, &InvalidTransitionError{State: stateOf(cmd)}
	}

	var out *commanddom.Command
	switch t {
	case TransitionClaim:
		out, err = s.Acknowledge(ctx, in.TenantID, in.SensorID, in.CommandID)
	case TransitionStart:
		out, err = s.Start(ctx, in.TenantID, in.SensorID, in.CommandID)
	case TransitionComplete:
		out, err = s.Complete(ctx, CompleteInput{TenantID: in.TenantID, SensorID: in.SensorID, CommandID: in.CommandID, Result: in.Result, LeaseEpoch: in.LeaseEpoch})
	case TransitionFail:
		out, err = s.Fail(ctx, FailInput{TenantID: in.TenantID, SensorID: in.SensorID, CommandID: in.CommandID, ErrorMessage: in.ErrorMessage, LeaseEpoch: in.LeaseEpoch, Refusal: in.Refusal})
	}
	if err != nil {
		return nil, s.transitionError(ctx, t, in, err)
	}
	if t == TransitionClaim && s.jobs != nil {
		signed, err := s.signJob(ctx, in.SensorID, out)
		if err != nil {
			// Not handed out unsigned: back to pending, still addressed to
			// this sensor only if it was before the claim.
			s.unclaim(ctx, out.TenantID, out.ID, in.SensorID, cmd.SensorID != nil)
			return nil, err
		}
		out = signed
	}
	return &TransitionResult{Command: out}, nil
}

// transitionAllowed is the RFC-029 §4.4 table for a state other than the
// transition's own target.
func transitionAllowed(t Transition, cmd *commanddom.Command, mine bool) bool {
	switch cmd.Status {
	case commanddom.CommandStatusPending:
		if cmd.IsExpired() {
			return false
		}
		return t == TransitionClaim || (t == TransitionFail && mine)
	case commanddom.CommandStatusAcknowledged:
		return mine && (t == TransitionStart || t == TransitionFail)
	case commanddom.CommandStatusRunning:
		return mine && (t == TransitionComplete || t == TransitionFail)
	}
	return false
}

// transitionError maps an error of the delegated v1 operation. The state can
// change between the read above and the write (a concurrent claim, a cancel,
// the expiry job), so a refused write re-reads the state it lost to.
func (s *Service) transitionError(ctx context.Context, t Transition, in TransitionInput, err error) error {
	if errors.Is(err, shared.ErrNotFound) {
		return err
	}
	if !errors.Is(err, shared.ErrConflict) && !errors.Is(err, shared.ErrValidation) {
		return err
	}
	cmd, gerr := s.Get(ctx, in.TenantID, in.CommandID)
	if gerr != nil {
		return gerr
	}
	if t == TransitionClaim && errors.Is(err, shared.ErrConflict) {
		return ErrCommandClaimed
	}
	if ensureSensorOwnsCommand(cmd, in.SensorID) != nil {
		// Claimed by another sensor in the meantime.
		if t == TransitionClaim {
			return ErrCommandClaimed
		}
		return shared.ErrNotFound
	}
	return &InvalidTransitionError{State: stateOf(cmd)}
}

// stateOf is the state a sensor is told: a pending command past its expiry is
// "expired" even before the expiry job flips it.
func stateOf(cmd *commanddom.Command) string {
	if cmd.Status == commanddom.CommandStatusPending && cmd.IsExpired() {
		return string(commanddom.CommandStatusExpired)
	}
	return string(cmd.Status)
}

// sameTransitionBody reports whether a replay carries what the first request
// stored: the same result (semantically equal JSON) for complete, the same
// stored message for fail. Claim and start have no body.
func sameTransitionBody(t Transition, cmd *commanddom.Command, in TransitionInput) bool {
	switch t {
	case TransitionComplete:
		return sameJSON(cmd.Result, in.Result)
	case TransitionFail:
		return cmd.ErrorMessage == truncateUTF8(in.ErrorMessage, MaxFailErrorMessageBytes)
	}
	return true
}

// sameJSON compares two JSON values semantically; empty and null are equal.
// jsonb storage reorders keys and drops whitespace, so bytes cannot be
// compared.
func sameJSON(a, b json.RawMessage) bool {
	a, b = bytes.TrimSpace(a), bytes.TrimSpace(b)
	aNull := len(a) == 0 || bytes.Equal(a, []byte("null"))
	bNull := len(b) == 0 || bytes.Equal(b, []byte("null"))
	if aNull || bNull {
		return aNull == bNull
	}
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// ReleaseInput is a sensor handing a claimed or running command back.
type ReleaseInput struct {
	TenantID  string
	SensorID  string
	CommandID string
	Reason    string
}

// MaxReleaseReasonBytes bounds the reason stored with a released command.
const MaxReleaseReasonBytes = 200

// Releaser is the repository side of a release (CommandRepository).
type Releaser interface {
	// ReleaseForSensor returns the command to pending and unpins it, only if
	// it is acknowledged or running and held by sensorID; false otherwise.
	ReleaseForSensor(ctx context.Context, tenantID, commandID shared.ID, sensorID, reason string) (bool, error)
}

// Release hands a command the sensor holds back to the queue at once
// (RFC-030 §5.12): pending, unpinned, its zone kept, so another eligible
// sensor can claim it without waiting for the stuck-command reaper. It is
// idempotent: once released, a repeat by the same sensor answers the command
// as it is (Replayed) as long as nobody else holds it. Errors:
// shared.ErrNotFound (unknown, or held by another sensor),
// *InvalidTransitionError (not acknowledged or running).
func (s *Service) Release(ctx context.Context, in ReleaseInput) (*TransitionResult, error) {
	rel, ok := s.repo.(Releaser)
	if !ok {
		return nil, fmt.Errorf("%w: release is not supported by this repository", shared.ErrValidation)
	}
	cmd, err := s.Get(ctx, in.TenantID, in.CommandID)
	if err != nil {
		return nil, err
	}
	if err := ensureSensorOwnsCommand(cmd, in.SensorID); err != nil {
		return nil, err
	}
	if cmd.SensorID == nil {
		// Unpinned: already released (by this sensor or the reaper), or never
		// claimed. Nothing to hand back.
		if cmd.Status == commanddom.CommandStatusPending {
			return &TransitionResult{Command: cmd, Replayed: true}, nil
		}
		return nil, &InvalidTransitionError{State: stateOf(cmd)}
	}
	if cmd.Status != commanddom.CommandStatusAcknowledged && cmd.Status != commanddom.CommandStatusRunning {
		return nil, &InvalidTransitionError{State: stateOf(cmd)}
	}
	reason := "released by sensor"
	if r := truncateUTF8(in.Reason, MaxReleaseReasonBytes); r != "" {
		reason += ": " + r
	}
	released, err := rel.ReleaseForSensor(ctx, cmd.TenantID, cmd.ID, in.SensorID, reason)
	if err != nil {
		return nil, err
	}
	if !released {
		// The state changed between the read and the write.
		return nil, s.transitionError(ctx, TransitionFail, TransitionInput{TenantID: in.TenantID, SensorID: in.SensorID, CommandID: in.CommandID},
			shared.NewDomainError("CONFLICT", "command state changed", shared.ErrConflict))
	}
	out, err := s.Get(ctx, in.TenantID, in.CommandID)
	if err != nil {
		return nil, err
	}
	return &TransitionResult{Command: out}, nil
}

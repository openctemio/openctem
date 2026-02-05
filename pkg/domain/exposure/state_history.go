package exposure

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// StateHistory represents an audit trail entry for exposure state changes.
type StateHistory struct {
	id              shared.ID
	exposureEventID shared.ID
	previousState   State
	newState        State
	changedBy       *shared.ID
	reason          string
	createdAt       time.Time
}

// NewStateHistory creates a new StateHistory entry.
func NewStateHistory(
	exposureEventID shared.ID,
	previousState State,
	newState State,
	changedBy *shared.ID,
	reason string,
) (*StateHistory, error) {
	if exposureEventID.IsZero() {
		return nil, fmt.Errorf("%w: exposure event ID is required", shared.ErrValidation)
	}
	if !previousState.IsValid() {
		return nil, fmt.Errorf("%w: invalid previous state", shared.ErrValidation)
	}
	if !newState.IsValid() {
		return nil, fmt.Errorf("%w: invalid new state", shared.ErrValidation)
	}

	return &StateHistory{
		id:              shared.NewID(),
		exposureEventID: exposureEventID,
		previousState:   previousState,
		newState:        newState,
		changedBy:       changedBy,
		reason:          reason,
		createdAt:       time.Now().UTC(),
	}, nil
}

// ReconstituteStateHistory recreates a StateHistory from persistence.
func ReconstituteStateHistory(
	id shared.ID,
	exposureEventID shared.ID,
	previousState State,
	newState State,
	changedBy *shared.ID,
	reason string,
	createdAt time.Time,
) *StateHistory {
	return &StateHistory{
		id:              id,
		exposureEventID: exposureEventID,
		previousState:   previousState,
		newState:        newState,
		changedBy:       changedBy,
		reason:          reason,
		createdAt:       createdAt,
	}
}

// ID returns the history entry ID.
func (h *StateHistory) ID() shared.ID {
	return h.id
}

// ExposureEventID returns the exposure event ID.
func (h *StateHistory) ExposureEventID() shared.ID {
	return h.exposureEventID
}

// PreviousState returns the previous state.
func (h *StateHistory) PreviousState() State {
	return h.previousState
}

// NewState returns the new state.
func (h *StateHistory) NewState() State {
	return h.newState
}

// ChangedBy returns who changed the state.
func (h *StateHistory) ChangedBy() *shared.ID {
	return h.changedBy
}

// Reason returns the reason for the change.
func (h *StateHistory) Reason() string {
	return h.reason
}

// CreatedAt returns when the change occurred.
func (h *StateHistory) CreatedAt() time.Time {
	return h.createdAt
}

package notification

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for notification module.
var (
	// ErrOutboxNotFound is returned when an outbox entry is not found.
	ErrOutboxNotFound = fmt.Errorf("%w: outbox entry not found", shared.ErrNotFound)

	// ErrOutboxAlreadyProcessed is returned when trying to process an already processed outbox entry.
	ErrOutboxAlreadyProcessed = fmt.Errorf("%w: outbox entry already processed", shared.ErrConflict)

	// ErrOutboxLocked is returned when an outbox entry is locked by another worker.
	ErrOutboxLocked = fmt.Errorf("%w: outbox entry is locked by another worker", shared.ErrConflict)

	// ErrInvalidOutboxStatus is returned when an invalid status transition is attempted.
	ErrInvalidOutboxStatus = fmt.Errorf("%w: invalid outbox status transition", shared.ErrValidation)

	// ErrEventNotFound is returned when a notification event is not found.
	ErrEventNotFound = fmt.Errorf("%w: notification event not found", shared.ErrNotFound)
)

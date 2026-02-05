package module

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors.
var (
	ErrPlanNotFound         = fmt.Errorf("%w: plan not found", shared.ErrNotFound)
	ErrPlanSlugExists       = fmt.Errorf("%w: plan slug already exists", shared.ErrConflict)
	ErrModuleNotFound       = fmt.Errorf("%w: module not found", shared.ErrNotFound)
	ErrEventTypeNotFound    = fmt.Errorf("%w: event type not found", shared.ErrNotFound)
	ErrSubscriptionNotFound = fmt.Errorf("%w: subscription not found", shared.ErrNotFound)
	ErrInvalidPlanID        = fmt.Errorf("%w: invalid plan ID format", shared.ErrValidation)
	ErrInvalidModuleID      = fmt.Errorf("%w: invalid module ID format", shared.ErrValidation)
	ErrInvalidSubModuleID   = fmt.Errorf("%w: invalid sub-module ID format", shared.ErrValidation)
)

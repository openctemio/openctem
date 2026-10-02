package compliance

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

var (
	ErrFrameworkNotFound    = fmt.Errorf("%w: framework not found", shared.ErrNotFound)
	ErrControlNotFound      = fmt.Errorf("%w: control not found", shared.ErrNotFound)
	ErrAssessmentNotFound   = fmt.Errorf("%w: assessment not found", shared.ErrNotFound)
	ErrMappingNotFound      = fmt.Errorf("%w: mapping not found", shared.ErrNotFound)
	ErrSystemFrameworkReadOnly = fmt.Errorf("%w: system frameworks cannot be modified", shared.ErrForbidden)
	ErrMappingAlreadyExists = fmt.Errorf("%w: finding is already mapped to this control", shared.ErrConflict)
)

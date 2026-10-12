package definition

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var (
	// ErrNotFound: no definition visible to the caller has that id or
	// identifier. A tenant definition of another tenant is "not found", never
	// "forbidden", so its existence does not leak.
	ErrNotFound = fmt.Errorf("definition %w", shared.ErrNotFound)
	// ErrInvalid wraps every validation failure.
	ErrInvalid = fmt.Errorf("definition: %w", shared.ErrValidation)
	// ErrNotWritable: the caller may not change this definition (it is global
	// and the caller is a tenant, or it belongs to another tenant).
	ErrNotWritable = fmt.Errorf("definition is not writable by this tenant: %w", shared.ErrForbidden)
	// ErrAlreadyExists: the scope already has a definition with that
	// (namespace, external id).
	ErrAlreadyExists = fmt.Errorf("definition %w", shared.ErrAlreadyExists)
)

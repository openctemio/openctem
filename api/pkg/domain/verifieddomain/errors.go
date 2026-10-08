package verifieddomain

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var (
	// ErrNotFound is returned when no matching verified-domain row exists.
	ErrNotFound = fmt.Errorf("%w: verified domain not found", shared.ErrNotFound)
	// ErrAlreadyExists is returned when the tenant already has a row for the domain.
	ErrAlreadyExists = fmt.Errorf("%w: domain already added for this tenant", shared.ErrConflict)
	// ErrInvalidDomain is returned when a domain fails normalization/validation.
	ErrInvalidDomain = fmt.Errorf("%w: invalid domain", shared.ErrValidation)
	// ErrBlockedDomain is returned when a shared/public consumer domain is submitted;
	// such domains can never be owned by a single tenant.
	ErrBlockedDomain = fmt.Errorf("%w: shared/public domain cannot be verified", shared.ErrValidation)
	// ErrDomainClaimed is returned when another organization holds the domain
	// verified for SSO, or lost its proof less than ClaimDisputeWindow ago.
	ErrDomainClaimed = fmt.Errorf("%w: domain is claimed by another organization", shared.ErrConflict)
)

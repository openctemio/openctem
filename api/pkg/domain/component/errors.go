package component

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for component.
var (
	ErrComponentNotFound      = fmt.Errorf("component %w", shared.ErrNotFound)
	ErrComponentAlreadyExists = fmt.Errorf("component %w", shared.ErrAlreadyExists)
	ErrDependencyNotFound     = fmt.Errorf("dependency %w", shared.ErrNotFound)
)

// NotFoundError returns a not found error with the component ID.
func NotFoundError(id shared.ID) error {
	return shared.NewDomainError(
		"COMPONENT_NOT_FOUND",
		fmt.Sprintf("component with id %s not found", id.String()),
		ErrComponentNotFound,
	)
}

// AlreadyExistsError returns an already exists error with the component PURL.
func AlreadyExistsError(purl string) error {
	return shared.NewDomainError(
		"COMPONENT_ALREADY_EXISTS",
		fmt.Sprintf("component with purl %s already exists", purl),
		ErrComponentAlreadyExists,
	)
}

// NotFoundByPURLError returns a not found error with the component PURL.
func NotFoundByPURLError(purl string) error {
	return shared.NewDomainError(
		"COMPONENT_NOT_FOUND",
		fmt.Sprintf("component with purl %s not found", purl),
		ErrComponentNotFound,
	)
}

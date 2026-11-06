package findingsource

import "errors"

var (
	// ErrFindingSourceNotFound is returned when a finding source is not found.
	ErrFindingSourceNotFound = errors.New("finding source not found")

	// ErrFindingSourceCodeExists is returned when a finding source with the same code already exists.
	ErrFindingSourceCodeExists = errors.New("finding source with this code already exists")

	// ErrCategoryNotFound is returned when a category is not found.
	ErrCategoryNotFound = errors.New("category not found")

	// ErrCategoryCodeExists is returned when a category with the same code already exists.
	ErrCategoryCodeExists = errors.New("category with this code already exists")

	// ErrCannotDeleteSystemSource is returned when trying to delete a system finding source.
	ErrCannotDeleteSystemSource = errors.New("cannot delete system finding source")

	// ErrCannotModifySystemSource is returned when trying to modify certain fields of a system source.
	ErrCannotModifySystemSource = errors.New("cannot modify system finding source")

	// ErrCategoryHasFindingSources is returned when trying to delete a category that has finding sources.
	ErrCategoryHasFindingSources = errors.New("category has associated finding sources")

	// ErrInvalidFindingSource is returned when a finding source code is not valid.
	ErrInvalidFindingSource = errors.New("invalid finding source code")
)

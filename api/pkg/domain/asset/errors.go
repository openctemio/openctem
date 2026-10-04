package asset

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Domain-specific errors for asset.
var (
	ErrAssetNotFound      = fmt.Errorf("asset %w", shared.ErrNotFound)
	ErrAssetAlreadyExists = fmt.Errorf("asset %w", shared.ErrAlreadyExists)
)

// NotFoundError creates an asset not found error with the ID.
func NotFoundError(assetID shared.ID) error {
	return fmt.Errorf("%w: id=%s", ErrAssetNotFound, assetID.String())
}

// AlreadyExistsError creates an asset already exists error with the name.
func AlreadyExistsError(name string) error {
	return fmt.Errorf("%w: name=%s", ErrAssetAlreadyExists, name)
}

// HasFindingsError is returned when a person deletes an asset that still has
// findings (any status). Deleting it would erase the finding history, SLA
// evidence and remediation records, so the delete is refused and the asset
// should be archived instead (owner decision O3).
type HasFindingsError struct {
	AssetID      shared.ID
	FindingCount int64
}

func (e *HasFindingsError) Error() string {
	return fmt.Sprintf("asset %s has %d findings: archive it instead of deleting it", e.AssetID.String(), e.FindingCount)
}

// Unwrap makes the error a shared.ErrConflict.
func (e *HasFindingsError) Unwrap() error { return shared.ErrConflict }

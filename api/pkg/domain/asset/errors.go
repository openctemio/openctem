package asset

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
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

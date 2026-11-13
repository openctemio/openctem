package assettype

import "errors"

var (
	// ErrAssetTypeNotFound is returned when an asset type is not found.
	ErrAssetTypeNotFound = errors.New("asset type not found")

	// ErrAssetTypeCodeExists is returned when an asset type with the same code already exists.
	ErrAssetTypeCodeExists = errors.New("asset type with this code already exists")

	// ErrCategoryNotFound is returned when a category is not found.
	ErrCategoryNotFound = errors.New("category not found")

	// ErrCategoryCodeExists is returned when a category with the same code already exists.
	ErrCategoryCodeExists = errors.New("category with this code already exists")

	// ErrCannotDeleteSystemType is returned when trying to delete a system asset type.
	ErrCannotDeleteSystemType = errors.New("cannot delete system asset type")

	// ErrCannotModifySystemType is returned when trying to modify certain fields of a system type.
	ErrCannotModifySystemType = errors.New("cannot modify system asset type")

	// ErrCategoryHasAssetTypes is returned when trying to delete a category that has asset types.
	ErrCategoryHasAssetTypes = errors.New("category has associated asset types")
)

package shared

// DataScope narrows a read to the assets one user may see in one tenant:
// the rows of user_accessible_assets for (TenantID, UserID). It is the
// resolved form of the Layer 2 (group) data scope.
//
// A nil *DataScope means "unrestricted" (an administrator, an internal call,
// or a member with no scope assignment in a fail-open tenant). A non-nil
// scope always restricts: a member of a fail-closed tenant with no
// assignment gets a scope whose set is empty, so they see nothing.
//
// Findings, exposures, notifications and other asset-bound rows are in scope
// when their asset is.
type DataScope struct {
	TenantID ID
	UserID   ID
}

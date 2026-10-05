package shared

// DataScope narrows a read to the assets one user may see in one tenant:
// the rows of user_accessible_assets for (TenantID, UserID). It is the
// resolved form of the Layer 2 (group) data scope.
//
// A nil *DataScope means "unrestricted" (an administrator, a holder of a
// has_full_data_access role, or an internal call). A non-nil scope always
// restricts: a member with no scope row gets a scope whose set is empty, so
// they see nothing.
//
// Findings, exposures, notifications and other asset-bound rows are in scope
// when their asset is.
type DataScope struct {
	TenantID ID
	UserID   ID
}

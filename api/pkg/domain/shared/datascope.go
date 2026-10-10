package shared

// DataScope narrows a read to the assets one user may see in one tenant:
// the rows of user_accessible_assets for (TenantID, UserID). It is the
// resolved form of the Layer 2 (group) data scope.
//
// A nil *DataScope means "unrestricted" (an owner, or an internal call; an
// administrator or a holder of a has_full_data_access role while nothing is
// hidden from them). A non-nil scope restricts: a member with no scope row
// gets a scope whose set is empty, so they see nothing.
//
// Assets of a private bug-bounty program that are only the program's
// (program-only) are hidden from everyone but the program's members and the
// organization's owners (RFC-065 §15.3). An administrator or full-data
// caller from whom such assets are hidden gets a scope with Unrestricted
// set: every asset of the tenant except the hidden ones. A restricted scope
// never admits a hidden asset either, whatever its scope rows say.
//
// Findings, exposures, notifications and other asset-bound rows are in scope
// when their asset is.
type DataScope struct {
	TenantID ID
	UserID   ID
	// Unrestricted: every asset of the tenant except the ones hidden from
	// UserID (private program assets of programs they are not a member of).
	Unrestricted bool
}

// Restricted reports whether the scope limits the caller to their scope
// rows (false for nil and for an Unrestricted scope).
func (s *DataScope) Restricted() bool { return s != nil && !s.Unrestricted }

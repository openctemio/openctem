package flagged

// Minimal stand-ins so the package type-checks without importing the
// real codebase. The analyzer looks at signature names and parameter
// *names*, so these don't have to match domain types exactly.

type ctx struct{}
type ID string
type Thing struct{}

type Repository struct{}

// The F-310 analyzer must flag this declaration.
func (r *Repository) GetByID(c ctx, id ID) (*Thing, error) { // want `GetByID has no tenantID parameter`
	_ = c
	_ = id
	return nil, nil
}

// Same class — UpdateByID without tenant.
func (r *Repository) UpdateByID(c ctx, id ID, t *Thing) error { // want `UpdateByID has no tenantID parameter`
	_ = c
	_ = id
	_ = t
	return nil
}

// DeleteByID — same class.
func (r *Repository) DeleteByID(c ctx, id ID) error { // want `DeleteByID has no tenantID parameter`
	_ = c
	_ = id
	return nil
}

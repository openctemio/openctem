package safe

type ctx struct{}
type ID string
type Thing struct{}

type Repository struct{}

// Safe #1: takes tenantID — analyzer accepts (no diagnostic).
func (r *Repository) GetByID(c ctx, tenantID ID, id ID) (*Thing, error) {
	_ = c
	_ = tenantID
	_ = id
	return nil, nil
}

// Safe #2: opt-out directive above declaration.
//
//getbyid:unsafe -- platform-level lookup, documented.
func (r *Repository) DeleteByID(c ctx, id ID) error {
	_ = c
	_ = id
	return nil
}

// Safe #3: method name is not in the flagged set.
func (r *Repository) FindByName(c ctx, name string) (*Thing, error) {
	_ = c
	_ = name
	return nil, nil
}

// Safe #4: tenant alias (parameter name contains "tenant").
func (r *Repository) UpdateByID(c ctx, tenant ID, id ID, t *Thing) error {
	_ = c
	_ = tenant
	_ = id
	_ = t
	return nil
}

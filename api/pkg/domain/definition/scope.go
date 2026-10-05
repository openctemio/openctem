package definition

import "github.com/openctemio/openctem/api/pkg/domain/shared"

// GlobalScopeKey is the scope key of a global definition: the nil UUID. The
// schema stores it in scope_tenant_id / definition_scope so that foreign keys
// can require "global or my tenant" (a key column that is NULL is never
// checked).
const GlobalScopeKey = "00000000-0000-0000-0000-000000000000"

// Scope says who a definition (or an identifier, relation or taxonomy link)
// belongs to: the platform (global) or one tenant.
type Scope struct {
	tenantID shared.ID
}

// Global is the platform scope: visible to every tenant, writable by none.
func Global() Scope { return Scope{} }

// TenantScope is one tenant's scope.
func TenantScope(tenantID shared.ID) Scope { return Scope{tenantID: tenantID} }

// IsGlobal reports whether s is the platform scope.
func (s Scope) IsGlobal() bool { return s.tenantID.IsZero() }

// TenantID returns the owning tenant; zero for a global scope.
func (s Scope) TenantID() shared.ID { return s.tenantID }

// Key returns the scope key the schema stores (GlobalScopeKey for global).
func (s Scope) Key() string {
	if s.IsGlobal() {
		return GlobalScopeKey
	}
	return s.tenantID.String()
}

// VisibleTo reports whether tenant may read something in scope s: everything
// global, and its own.
func (s Scope) VisibleTo(tenant shared.ID) bool {
	return s.IsGlobal() || (!tenant.IsZero() && s.tenantID.Equals(tenant))
}

// WritableBy reports whether tenant may change something in scope s: only
// its own. Global content is written by platform feeds and imports, never
// through a tenant.
func (s Scope) WritableBy(tenant shared.ID) bool {
	return !s.IsGlobal() && !tenant.IsZero() && s.tenantID.Equals(tenant)
}

// ScopeFromKey is the inverse of Key.
func ScopeFromKey(key string) (Scope, error) {
	if key == "" || key == GlobalScopeKey {
		return Global(), nil
	}
	id, err := shared.IDFromString(key)
	if err != nil {
		return Scope{}, err
	}
	return TenantScope(id), nil
}

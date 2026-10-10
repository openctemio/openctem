package module

// The module registry (RFC-064): configs/modules/<id>.yaml is the single
// declaration of every module. cmd/gen-modules turns it into
// registry_generated.go (the constants and Registry), the web constants and
// the `modules` rows; the maps below are derived from Registry so no second
// list can drift from it.

// Definition is one module of the registry.
type Definition struct {
	ID           string
	Slug         string
	Name         string
	Description  string
	Icon         string
	Category     string
	DisplayOrder int
	// Core: always on, cannot be switched off.
	Core bool
	// Parent is the parent module id of a sub-module ("" for a top-level one).
	Parent  string
	Release ReleaseStatus
	// UserFacing: listed on Settings > Modules.
	UserFacing bool
	// Permission is the read permission that shows the module.
	Permission string
	Depends    []Dependency
	// Routes are the REST path prefixes the module gates; "{}" stands for a
	// path parameter.
	Routes []string
	// MCP lists the MCP tools and prompts of the module.
	MCP []string
	// Jobs lists the background controllers the module owns.
	Jobs []string
}

// Lookup returns the registry definition of a module id.
func Lookup(id string) (Definition, bool) {
	d, ok := registryByID[id]
	return d, ok
}

var registryByID = func() map[string]Definition {
	m := make(map[string]Definition, len(Registry))
	for _, d := range Registry {
		m[d.ID] = d
	}
	return m
}()

func registryIDs(keep func(Definition) bool) map[string]bool {
	m := make(map[string]bool)
	for _, d := range Registry {
		if keep(d) {
			m[d.ID] = true
		}
	}
	return m
}

// CoreModuleIDs are the modules that are always on and cannot be disabled.
var CoreModuleIDs = registryIDs(func(d Definition) bool { return d.Core })

// UserFacingModuleIDs are the modules listed on Settings > Modules (core
// ones shown as "Always on").
var UserFacingModuleIDs = registryIDs(func(d Definition) bool { return d.UserFacing })

// ModulePermissionMapping maps a module id to the read permission that shows
// it in the sidebar. These permissions must exist in the permission catalog.
var ModulePermissionMapping = func() map[string]string {
	m := make(map[string]string)
	for _, d := range Registry {
		if d.Permission != "" {
			m[d.ID] = d.Permission
		}
	}
	return m
}()

// ModuleDependencies is the dependency graph, keyed by the dependent module.
// Core modules are never keys: the core check short-circuits ValidateToggle.
var ModuleDependencies = func() map[string][]Dependency {
	m := make(map[string][]Dependency)
	for _, d := range Registry {
		if len(d.Depends) > 0 {
			m[d.ID] = d.Depends
		}
	}
	return m
}()

package authzdoc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// RoleInfo is a built-in role or a role template, as the reference shows it.
type RoleInfo struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"` // "system" or "template"
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Personas          []string `json:"personas,omitempty"`
	HasFullDataAccess bool     `json:"has_full_data_access"`
	AdminBypass       bool     `json:"admin_bypass,omitempty"`
	Permissions       []string `json:"permissions"`
}

// RouteDoc is one route with what it requires and who passes.
type RouteDoc struct {
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	Gate        Gate        `json:"gate"`
	DataSurface DataSurface `json:"data_scope"`
	// Ungated says why a route carries no permission gate (public, the
	// caller's own data, a machine credential), from the authz coverage gate.
	Ungated string `json:"ungated,omitempty"`
	// Roles lists the built-in roles and templates whose permissions pass
	// the gate (before module, data scope and step-up). Left out of the JSON:
	// the web computes it from the gate and the role list.
	Roles []string `json:"-"`
}

// FeatureDoc is one feature page.
type FeatureDoc struct {
	Feature
	Modules     []string   `json:"modules,omitempty"`
	Permissions []string   `json:"permissions"`
	Routes      []RouteDoc `json:"routes"`
}

// Reference is the whole generated authorization reference.
type Reference struct {
	Version     int               `json:"version"`
	Permissions []PermissionInfo  `json:"permissions"`
	Roles       []RoleInfo        `json:"roles"`
	Features    []FeatureDoc      `json:"features"`
	Personas    []Persona         `json:"personas"`
	Teams       []TeamPattern     `json:"teams"`
	DataScopes  map[string]string `json:"data_scope_classes"`
}

// pendingRoles are roles personas may name before they exist (a built-in role
// another change is adding). Rendered as named; checked by the tests.
var pendingRoles = map[string]string{}

// Roles returns the built-in roles followed by the role templates.
func Roles() []RoleInfo {
	sys, tpls := permission.SystemRoles(), permission.RoleTemplates()
	out := make([]RoleInfo, 0, len(sys)+len(tpls))
	for _, r := range sys {
		out = append(out, RoleInfo{
			ID: r.Slug, Kind: "system", Name: r.Name, Description: r.Description,
			HasFullDataAccess: r.HasFullDataAccess, AdminBypass: r.AdminBypass,
			Permissions: sortedStrings(permission.ToStrings(r.Permissions)),
		})
	}
	for _, t := range tpls {
		out = append(out, RoleInfo{
			ID: t.ID, Kind: "template", Name: t.Name, Description: t.Description, Personas: t.Personas,
			HasFullDataAccess: t.HasFullDataAccess,
			Permissions:       sortedStrings(permission.ToStrings(t.Permissions)),
		})
	}
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// Passes reports whether a role's permissions pass a gate's permission and
// team-role checks. Owner and admin pass every permission check; only they
// hold a team role of admin or above. Other named gates (campaign role,
// platform administrator) are not decided here.
func (r RoleInfo) Passes(g Gate) bool {
	if g.MinRole != "" {
		if r.Kind != "system" || !r.AdminBypass {
			return false
		}
		if g.MinRole == "owner" && r.ID != "owner" {
			return false
		}
	}
	if r.AdminBypass {
		return true
	}
	held := map[string]bool{}
	for _, p := range r.Permissions {
		held[p] = true
	}
	for _, p := range g.Permissions {
		if !held[p] {
			return false
		}
	}
	for _, grp := range g.AnyOf {
		ok := false
		for _, p := range grp {
			ok = ok || held[p]
		}
		if !ok {
			return false
		}
	}
	return true
}

// Build reads the source under apiRoot and assembles the reference.
func Build(apiRoot string) (*Reference, error) {
	routes, err := ParseRoutes(apiRoot)
	if err != nil {
		return nil, err
	}
	surfaces, err := loadDataSurfaces(apiRoot)
	if err != nil {
		return nil, err
	}
	text, err := loadPermissionText(apiRoot)
	if err != nil {
		return nil, err
	}
	allow, err := loadAllowlist(apiRoot)
	if err != nil {
		return nil, err
	}

	ref := &Reference{Version: 1, Personas: Personas, Teams: TeamPatterns, DataScopes: DataScopeClasses, Roles: Roles()}
	for _, p := range permission.AllPermissions() {
		info, ok := text[string(p)]
		if !ok {
			info = PermissionInfo{ID: string(p), Module: strings.SplitN(string(p), ":", 2)[0], Name: string(p)}
		}
		info.AdminOnly = permission.IsAdminOnly(string(p))
		ref.Permissions = append(ref.Permissions, info)
	}
	sort.Slice(ref.Permissions, func(i, j int) bool { return ref.Permissions[i].ID < ref.Permissions[j].ID })

	byFeature := map[string]*FeatureDoc{}
	for _, f := range Features {
		byFeature[f.ID] = &FeatureDoc{Feature: f}
	}
	var unclassified []string
	for _, r := range routes {
		f, ok := FeatureOf(r)
		if !ok {
			unclassified = append(unclassified, r.Key()+" ("+r.Register+")")
			continue
		}
		ds, _ := lookupDataSurface(surfaces, r.Method, r.RawPath)
		rd := RouteDoc{Method: r.Method, Path: r.Path, Gate: r.Gate, DataSurface: ds, Roles: []string{}}
		if r.Gated() {
			for _, role := range ref.Roles {
				if role.Passes(r.Gate) {
					rd.Roles = append(rd.Roles, role.ID)
				}
			}
		} else {
			rd.Ungated = allow.reason(r.Method, r.RawPath)
		}
		fd := byFeature[f.ID]
		fd.Routes = append(fd.Routes, rd)
	}
	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		return nil, fmt.Errorf("routes in no feature (add their register function to authzdoc.Features): %s", strings.Join(unclassified, ", "))
	}
	for _, f := range Features {
		fd := byFeature[f.ID]
		mods, perms := map[string]bool{}, map[string]bool{}
		for _, r := range fd.Routes {
			for _, m := range r.Gate.Modules {
				mods[m] = true
			}
			for _, p := range r.Gate.Permissions {
				perms[p] = true
			}
			for _, g := range r.Gate.AnyOf {
				for _, p := range g {
					perms[p] = true
				}
			}
		}
		fd.Modules = keys(mods)
		fd.Permissions = keys(perms)
		if fd.Permissions == nil {
			fd.Permissions = []string{}
		}
		ref.Features = append(ref.Features, *fd)
	}
	return ref, nil
}

func keys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RoleName returns the display name of a role id (system slug, template id or
// a pending built-in role).
func (ref *Reference) RoleName(id string) string {
	for _, r := range ref.Roles {
		if r.ID == id {
			return r.Name
		}
	}
	if n, ok := pendingRoles[id]; ok {
		return n
	}
	return id
}

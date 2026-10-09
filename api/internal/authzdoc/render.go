package authzdoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// JSON renders the reference for the web console (stable, compact output).
func (ref *Reference) JSON() ([]byte, error) {
	b, err := json.Marshal(ref)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Page is one generated markdown file, path relative to the output root.
type Page struct {
	Path    string
	Content []byte
}

// MarkdownOptions shape the markdown output.
type MarkdownOptions struct {
	// FrontMatter adds the documentation site's front matter (parent pages,
	// navigation order).
	FrontMatter bool
}

const (
	yes            = "yes"
	referenceTitle = "Authorization reference"
	identityTitle  = "Identity and access"
	generatedNote  = "<!-- Generated from the OpenCTEM source by `go run ./cmd/gen-authz-docs` in api/. Do not edit by hand. -->\n\n"
)

func frontMatter(opts MarkdownOptions, title, parent, grandParent string, order int, hasChildren bool) string {
	if !opts.FrontMatter {
		return ""
	}
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "title: %q\n", title)
	if parent != "" {
		fmt.Fprintf(&b, "parent: %q\n", parent)
	}
	if grandParent != "" {
		fmt.Fprintf(&b, "grand_parent: %q\n", grandParent)
	}
	if order > 0 {
		fmt.Fprintf(&b, "nav_order: %d\n", order)
	}
	if hasChildren {
		b.WriteString("has_children: true\n")
	}
	b.WriteString("---\n\n")
	return b.String()
}

// mdCell escapes a table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func code(s string) string { return "`" + s + "`" }

func codes(ss []string) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = code(s)
	}
	return strings.Join(out, ", ")
}

func (ref *Reference) roleNames(ids []string) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = ref.RoleName(id)
	}
	return strings.Join(out, ", ")
}

// gateText describes a route's gate in words.
func gateText(g Gate) string {
	parts := make([]string, 0, 2+len(g.AnyOf)+len(g.Other))
	if len(g.Permissions) > 0 {
		parts = append(parts, codes(g.Permissions))
	}
	for _, grp := range g.AnyOf {
		parts = append(parts, "one of "+codes(grp))
	}
	if g.MinRole != "" {
		parts = append(parts, "team role "+g.MinRole)
	}
	for _, o := range g.Other {
		parts = append(parts, otherGateText[o])
	}
	if len(parts) == 0 {
		return "signed in (no permission)"
	}
	return strings.Join(parts, " + ")
}

var otherGateText = map[string]string{
	"permission_or_self":  "the permission, or the caller's own record",
	"campaign_role":       "a campaign role",
	"platform_admin":      "platform administrator",
	"platform_admin_role": "platform administrator role",
	"team_role":           "a team role",
}

// Markdown renders the documentation pages.
func (ref *Reference) Markdown(opts MarkdownOptions) []Page {
	pages := make([]Page, 0, len(ref.Features)+3)
	pages = append(pages, ref.indexPage(opts), ref.matrixPage(opts), ref.personasPage(opts))
	for i, f := range ref.Features {
		pages = append(pages, ref.featurePage(opts, i, f))
	}
	return pages
}

func (ref *Reference) indexPage(opts MarkdownOptions) Page {
	var idx bytes.Buffer
	idx.WriteString(frontMatter(opts, referenceTitle, identityTitle, "", 3, true))
	idx.WriteString(generatedNote)
	idx.WriteString("# " + referenceTitle + "\n\n")
	idx.WriteString("Every request inside an organization passes up to five checks, in this order:\n\n")
	idx.WriteString("1. **Permission** (what you may do): the union of the permissions of your roles. Owners and administrators pass every permission check.\n")
	idx.WriteString("2. **Module**: the feature is enabled for the organization. A module switch is a feature setting, not a security boundary.\n")
	idx.WriteString("3. **Data scope** (what you may see): the assets of your teams, plus any per-asset grant, unless a role gives full data access. An asset outside your scope answers 404, never 403.\n")
	idx.WriteString("4. **Step-up**: some actions need a recent sign-in.\n")
	idx.WriteString("5. **Approval**: some changes need a second person (risk acceptance, false positives, suppression rules, scope changes).\n\n")
	idx.WriteString("A refused permission answers 403 with `details.missing_permissions` (or `details.any_of`, `details.required_role`), so you can tell an administrator exactly what to grant.\n\n")
	idx.WriteString("- [Role and permission matrix](roles-matrix.md): the built-in roles, the role templates and every permission.\n")
	idx.WriteString("- [Personas](personas.md): who uses OpenCTEM and the roles, team and data scope recommended for each.\n\n")
	idx.WriteString("## Features\n\n| Feature | Modules | Routes |\n|---|---|---|\n")
	for _, f := range ref.Features {
		fmt.Fprintf(&idx, "| [%s](features/%s.md) | %s | %d |\n", f.Title, f.ID, codes(f.Modules), len(f.Routes))
	}
	idx.WriteString("\n## Data scope classes\n\n| Class | Meaning |\n|---|---|\n")
	for _, c := range []string{"scoped", "partial", "gap", "separate", "config", "system"} {
		fmt.Fprintf(&idx, "| %s | %s |\n", code(c), mdCell(ref.DataScopes[c]))
	}
	return Page{"index.md", idx.Bytes()}
}

func (ref *Reference) matrixPage(opts MarkdownOptions) Page {
	var m bytes.Buffer
	m.WriteString(frontMatter(opts, "Role and permission matrix", referenceTitle, identityTitle, 1, false))
	m.WriteString(generatedNote)
	m.WriteString("# Role and permission matrix\n\n")
	m.WriteString("**Built-in roles** cannot be edited. Every new member starts as a viewer.\n\n")
	m.WriteString("**Role templates** are starting points for custom roles (Settings > Roles > New role > Start from a template). A template grants nothing until a role is created from it, and nobody can create a role holding permissions they lack.\n\n")
	m.WriteString("A person may hold several roles; their permissions are the union. Roles never decide which assets someone sees, except roles with full data access. Teams decide that.\n\n")
	m.WriteString("| Role | Kind | Full data | For |\n|---|---|---|---|\n")
	for _, r := range ref.Roles {
		kind := "built-in"
		if r.Kind == "template" {
			kind = "template"
		}
		full := ""
		if r.HasFullDataAccess {
			full = yes
		}
		desc := r.Description
		if r.AdminBypass {
			desc += " Passes every permission check."
		}
		fmt.Fprintf(&m, "| **%s** (%s) | %s | %s | %s |\n", r.Name, code(r.ID), kind, full, mdCell(desc))
	}
	m.WriteString("\n## Separation of duties\n\n")
	m.WriteString("- The person who marks a fix applied (`findings:fix_apply`) is never the one who verifies it (`findings:verify`).\n")
	m.WriteString("- Risk acceptance and false positives are requested with `findings:status` and decided with `findings:approve`; no template holds both.\n")
	m.WriteString("- Suppression rules are written with `findings:suppressions:write` and approved with `findings:suppressions:approve`.\n")
	m.WriteString("- Scope is widened with `attack_surface:scope:write` and approved with `attack_surface:scope:approve`.\n")
	m.WriteString("- Nobody grants a role carrying a permission they do not hold; only the owner creates administrators.\n\n")
	m.WriteString("## Permissions\n\nColumns: built-in roles, then templates. Owner and administrator pass every check whatever their list says.\n\n")
	m.WriteString("| Permission | Description |")
	for _, r := range ref.Roles {
		m.WriteString(" " + r.ID + " |")
	}
	m.WriteString("\n|---|---|")
	for range ref.Roles {
		m.WriteString(":-:|")
	}
	m.WriteString("\n")
	held := make([]map[string]bool, len(ref.Roles))
	for i, r := range ref.Roles {
		held[i] = map[string]bool{}
		for _, p := range r.Permissions {
			held[i][p] = true
		}
	}
	for _, p := range ref.Permissions {
		desc := p.Name
		if p.Description != "" && p.Description != p.Name {
			desc += ": " + p.Description
		}
		if p.AdminOnly {
			desc += " (owner and administrators only)"
		}
		fmt.Fprintf(&m, "| %s | %s |", code(p.ID), mdCell(desc))
		for i, r := range ref.Roles {
			mark := ""
			switch {
			case held[i][p.ID]:
				mark = "✓"
			case r.AdminBypass:
				mark = "(✓)"
			}
			m.WriteString(" " + mark + " |")
		}
		m.WriteString("\n")
	}
	return Page{"roles-matrix.md", m.Bytes()}
}

func (ref *Reference) personasPage(opts MarkdownOptions) Page {
	var pp bytes.Buffer
	pp.WriteString(frontMatter(opts, "Personas", referenceTitle, identityTitle, 2, false))
	pp.WriteString(generatedNote)
	pp.WriteString("# Personas and recommended access\n\n")
	pp.WriteString("Give each person the **roles** for what they do, a **team** for what they see, and an **end date** when they come from outside. Roles combine: a person may hold several.\n\n")
	pp.WriteString("| Persona | Roles | Team | Data scope | Access |\n|---|---|---|---|---|\n")
	teamName := map[string]string{}
	for _, t := range ref.Teams {
		teamName[t.ID] = t.Name
	}
	for _, p := range ref.Personas {
		roles := ref.roleNames(p.Roles)
		if roles == "" {
			roles = "none (machine identity)"
		}
		fmt.Fprintf(&pp, "| **%s** | %s | %s | %s | %s |\n", p.Name, mdCell(roles), mdCell(teamName[p.Team]), mdCell(p.DataScope), mdCell(p.Access))
	}
	group := ""
	for _, p := range ref.Personas {
		if p.Group != group {
			group = p.Group
			pp.WriteString("\n## " + group + "\n")
		}
		fmt.Fprintf(&pp, "\n### %s\n\n%s\n\n", p.Name, p.Goal)
		if len(p.Stages) > 0 {
			fmt.Fprintf(&pp, "- **CTEM stages:** %s\n", strings.Join(p.Stages, ", "))
		}
		if len(p.Roles) > 0 {
			fmt.Fprintf(&pp, "- **Roles:** %s\n", ref.roleNames(p.Roles))
		}
		if p.Team != "" {
			fmt.Fprintf(&pp, "- **Team:** %s\n", teamName[p.Team])
		}
		fmt.Fprintf(&pp, "- **Sees:** %s\n- **Access:** %s\n", p.DataScope, p.Access)
		if len(p.MustNot) > 0 {
			fmt.Fprintf(&pp, "- **Must not:** %s\n", strings.Join(p.MustNot, "; "))
		}
	}
	pp.WriteString("\n## Recommended teams\n\nA team (access group) decides what its members see: the assets assigned to it, directly or by scope rules on tags and asset groups.\n\n")
	pp.WriteString("| Team | Type | Purpose | Assets | Usual roles | End date |\n|---|---|---|---|---|---|\n")
	for _, t := range ref.Teams {
		exp := ""
		if t.Expiring {
			exp = yes
		}
		fmt.Fprintf(&pp, "| %s | %s | %s | %s | %s | %s |\n", mdCell(t.Name), code(t.GroupType), mdCell(t.Purpose), mdCell(t.Assets), mdCell(ref.roleNames(t.Roles)), exp)
	}
	return Page{"personas.md", pp.Bytes()}
}

func (ref *Reference) featurePage(opts MarkdownOptions, i int, f FeatureDoc) Page {
	var b bytes.Buffer
	b.WriteString(frontMatter(opts, f.Title+" permissions", referenceTitle, identityTitle, 10+i, false))
	b.WriteString(generatedNote)
	fmt.Fprintf(&b, "# %s: permissions\n\n%s\n\n", f.Title, f.Description)
	if len(f.Stages) > 0 {
		fmt.Fprintf(&b, "- **CTEM stages:** %s\n", strings.Join(f.Stages, ", "))
	}
	if len(f.Modules) > 0 {
		fmt.Fprintf(&b, "- **Modules:** %s (the routes answer `403 MODULE_NOT_ENABLED` when the module is off)\n", codes(f.Modules))
	}
	if len(f.Permissions) > 0 {
		fmt.Fprintf(&b, "- **Permissions:** %s\n", codes(f.Permissions))
	}
	b.WriteString("\n## Who can do it\n\nBuilt-in roles and role templates whose permissions pass each route. Owner and administrator are included where the route allows them.\n\n")
	// Summary per permission: which roles hold it.
	if len(f.Permissions) > 0 {
		b.WriteString("| Permission | Roles |\n|---|---|\n")
		for _, p := range f.Permissions {
			var who []string
			for _, r := range ref.Roles {
				if r.Passes(Gate{Permissions: []string{p}}) {
					who = append(who, r.Name)
				}
			}
			fmt.Fprintf(&b, "| %s | %s |\n", code(p), mdCell(strings.Join(who, ", ")))
		}
	}
	b.WriteString("\n## Routes\n\n| Method | Path | Requires | Data scope | Step-up | Roles that pass |\n|---|---|---|---|---|---|\n")
	routes := append([]RouteDoc(nil), f.Routes...)
	sort.SliceStable(routes, func(a, c int) bool {
		if routes[a].Path != routes[c].Path {
			return routes[a].Path < routes[c].Path
		}
		return routes[a].Method < routes[c].Method
	})
	for _, r := range routes {
		step := ""
		if r.Gate.StepUp {
			step = yes
		}
		scope := r.DataSurface.Class
		if r.DataSurface.Note != "" {
			scope += ": " + r.DataSurface.Note
		}
		req, who := gateText(r.Gate), ref.roleNames(r.Roles)
		if r.Ungated != "" {
			req, who = "no permission: "+r.Ungated, "see Requires"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r.Method, code(r.Path), mdCell(req), mdCell(scope), step, mdCell(who))
	}
	return Page{"features/" + f.ID + ".md", b.Bytes()}
}

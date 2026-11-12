package routes

// The platform permission reference page (RFC-134) is generated from the
// catalog, the built-in roles and the console route inventory, and committed
// at docs/architecture/platform-permissions.md. This test fails when the page
// is stale; `make -C api platform-authz-docs` rewrites it.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
)

const platformReferencePath = "../../../../docs/architecture/platform-permissions.md"

func renderPlatformReference() string {
	var b strings.Builder
	b.WriteString("# Platform permission reference\n\n")
	b.WriteString("Generated from `pkg/domain/platformauthz` and `adminRoutePermissions`\n")
	b.WriteString("(`internal/infra/http/routes/admin_permissions.go`) by `make -C api platform-authz-docs`;\n")
	b.WriteString("do not edit by hand. Design: RFC-134. These permissions exist only on the\n")
	b.WriteString("console; the tenant permission reference never lists them.\n\n")
	b.WriteString("A baseline permission is usable by a console session that has not elevated.\n")
	b.WriteString("The others need an elevated session acting as a role that holds them (when\n")
	b.WriteString("elevation is required, the default).\n\n")

	roles := platformauthz.BuiltinRoles()
	b.WriteString("## Roles\n\n| Role | Name | Kind | Description |\n|---|---|---|---|\n")
	for _, r := range roles {
		kind := "additional"
		if r.Base {
			kind = "base (" + string(r.Tier) + ")"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.Key, r.Name, kind, r.Description)
	}

	b.WriteString("\n## Permissions by role\n\n| Permission | Baseline |")
	for _, r := range roles {
		fmt.Fprintf(&b, " `%s` |", r.Key)
	}
	b.WriteString("\n|---|---|")
	for range roles {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, d := range platformauthz.Catalog() {
		base := ""
		if d.Baseline {
			base = "yes"
		}
		fmt.Fprintf(&b, "| `%s` | %s |", d.Key, base)
		for _, r := range roles {
			mark := ""
			if platformauthz.RolePermissions(r.Key).Has(d.Key) {
				mark = "yes"
			}
			fmt.Fprintf(&b, " %s |", mark)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Permissions\n\n| Permission | What it allows |\n|---|---|\n")
	for _, d := range platformauthz.Catalog() {
		fmt.Fprintf(&b, "| `%s` | %s |\n", d.Key, d.Description)
	}

	b.WriteString("\n## Console routes\n\n`self`: the caller's own session, factors and elevation (a verified console\n")
	b.WriteString("session, no permission). `public`: a sign-in step before a session exists.\n\n")
	b.WriteString("| Route | Permission |\n|---|---|\n")
	keys := make([]string, 0, len(adminRoutePermissions))
	for k := range adminRoutePermissions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		pi, pj := strings.SplitN(keys[i], " ", 2), strings.SplitN(keys[j], " ", 2)
		if pi[1] != pj[1] {
			return pi[1] < pj[1]
		}
		return pi[0] < pj[0]
	})
	for _, k := range keys {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", k, adminRoutePermissions[k])
	}
	return b.String()
}

func TestPlatformPermissionReferenceUpToDate(t *testing.T) {
	want := renderPlatformReference()
	if os.Getenv("UPDATE_PLATFORM_AUTHZ_DOC") == "1" {
		if err := os.WriteFile(platformReferencePath, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(platformReferencePath)
	if err != nil || string(got) != want {
		t.Fatalf("docs/architecture/platform-permissions.md is stale: run make -C api platform-authz-docs (%v)", err)
	}
}

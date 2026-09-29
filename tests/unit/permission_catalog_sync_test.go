package unit

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/permission"
)

// The permission catalog lives in THREE hand-maintained places that must stay
// identical: the Go registry (permission.AllPermissions), the SQL seed
// migrations, and — separately tested on the UI side — the TS constants. They
// are in sync today only by discipline. This test locks the Go↔DB half: a PR
// that adds a Require(permission.X) + Go const but forgets the seed migration
// (or vice-versa) fails here instead of silently shipping a permission that can
// be enforced but never granted (or shown in the UI but never enforced).
//
// See docs/authz-audit.md AUTHZ-17.

// permSeedMigrations are the migrations that INSERT INTO permissions. A new
// permission-seeding migration MUST be added here (the list is asserted
// non-empty and every file must exist, so a typo fails loudly).
var permSeedMigrations = []string{
	"000005_permissions.up.sql",
	"000068_findings_approve_permission.up.sql",
	"000091_pentest_seeds.up.sql",
	"000093_compliance_seeds.up.sql",
	"000096_fix_applied_status.up.sql",
	"000153_ctem_permissions.up.sql",
}

// tupleID captures the FIRST single-quoted string of a VALUES tuple row, i.e.
// the permission id (id is always column 1 across every seed format:
// 3-col, 4-col, and with-is_active). Anchored to the row start so it never
// picks up the module_id (column 2) or a quoted word inside a description.
var tupleID = regexp.MustCompile(`^\s*\(\s*'([a-z][a-z0-9_]*(?::[a-z0-9_]+)+)'`)

func seededPermissionIDs(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	out := make(map[string]string) // id -> "file:line"
	for _, m := range permSeedMigrations {
		path := filepath.Join(root, "migrations", m)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read seed migration %s: %v (update permSeedMigrations if a file was renamed)", m, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if mm := tupleID.FindStringSubmatch(line); mm != nil {
				id := mm[1]
				if prev, dup := out[id]; dup {
					t.Errorf("permission %q seeded twice: %s and %s:%d", id, prev, m, i+1)
				}
				out[id] = m + ":" + itoa(i+1)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed zero permissions from seed migrations — the parser or file list is broken")
	}
	return out
}

func goRegistryPermissionIDs() map[string]bool {
	out := make(map[string]bool)
	for _, p := range permission.AllPermissions() {
		out[p.String()] = true
	}
	return out
}

func TestPermissionCatalog_GoMatchesDBSeed(t *testing.T) {
	db := seededPermissionIDs(t)
	code := goRegistryPermissionIDs()

	var inCodeNotDB, inDBNotCode []string
	for id := range code {
		if _, ok := db[id]; !ok {
			inCodeNotDB = append(inCodeNotDB, id)
		}
	}
	for id := range db {
		if !code[id] {
			inDBNotCode = append(inDBNotCode, id)
		}
	}
	sort.Strings(inCodeNotDB)
	sort.Strings(inDBNotCode)

	if len(inCodeNotDB) > 0 {
		t.Errorf("permissions referenced in Go (AllPermissions) but NOT seeded in any migration "+
			"— they can be enforced via Require() but never granted to a role:\n  %s\n"+
			"Fix: add them to a seed migration (and to the UI TS constants).",
			strings.Join(inCodeNotDB, "\n  "))
	}
	if len(inDBNotCode) > 0 {
		t.Errorf("permissions seeded in the DB but NOT present in Go AllPermissions() "+
			"— grantable but never enforced, i.e. dead codes:\n  %s\n"+
			"Fix: add the const to permission.AllPermissions() or remove the seed row.",
			strings.Join(inDBNotCode, "\n  "))
	}

	if len(inCodeNotDB) == 0 && len(inDBNotCode) == 0 {
		t.Logf("permission catalog in sync: %d codes (Go) == %d codes (DB seed)", len(code), len(db))
	}
}

// itoa avoids importing strconv just for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

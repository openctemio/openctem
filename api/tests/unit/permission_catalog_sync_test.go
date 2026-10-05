package unit

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
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
	"000231_scan_zones.up.sql",                     // sensors:zones:* (RFC-023 D16)
	"000232_credentials_reveal_permission.up.sql",  // findings:credentials:reveal
	"000267_scope_exclusion_approval.up.sql",       // attack_surface:scope:exclusions:approve
	"000774_dashboard_aggregate_permission.up.sql", // dashboard:aggregate (D6)
	"001063_ci_runner_identity.up.sql",             // scans:ci:* (RFC-051)
}

// permRenameMigrations rename permission ids in place (old id → new id) with
// a mapping table whose rows are ('old', 'new', ...). The renames are applied,
// in order, on top of the seeded ids.
var permRenameMigrations = []string{
	"000230_rename_agent_to_sensor.up.sql", // agents:* → sensors:* (RFC-023 §9.5)
}

// permRemoveMigrations delete permission ids. Each lists the removed ids as
// one-column VALUES rows ('id'), which tupleID parses; they are applied, in
// order, after the renames.
var permRemoveMigrations = []string{
	"000670_remove_group_permission_sets.up.sql",   // team:permission_sets:* (permissions come only from roles)
	"000772_remove_meaningless_permissions.up.sql", // billing/policies/compliance permissions that gate nothing
	"001032_remove_outbound_webhooks.up.sql",       // integrations:webhooks:* (outbound webhooks never delivered; owner decision B9)
}

var renameRow = regexp.MustCompile(`^\s*\(\s*'([a-z][a-z0-9_]*(?::[a-z0-9_]+)+)'\s*,\s*'([a-z][a-z0-9_]*(?::[a-z0-9_]+)+)'`)

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
	for _, m := range permRenameMigrations {
		data, err := os.ReadFile(filepath.Join(root, "migrations", m))
		if err != nil {
			t.Fatalf("read rename migration %s: %v", m, err)
		}
		renamed := 0
		for _, line := range strings.Split(string(data), "\n") {
			mm := renameRow.FindStringSubmatch(line)
			if mm == nil {
				continue
			}
			loc, ok := out[mm[1]]
			if !ok {
				t.Errorf("%s renames %q, which no seed migration creates", m, mm[1])
				continue
			}
			delete(out, mm[1])
			out[mm[2]] = loc + " (renamed by " + m + ")"
			renamed++
		}
		if renamed == 0 {
			t.Errorf("%s is listed as renaming permissions but no rename row was parsed", m)
		}
	}
	for _, m := range permRemoveMigrations {
		data, err := os.ReadFile(filepath.Join(root, "migrations", m))
		if err != nil {
			t.Fatalf("read remove migration %s: %v", m, err)
		}
		removed := 0
		for _, line := range strings.Split(string(data), "\n") {
			mm := tupleID.FindStringSubmatch(line)
			if mm == nil {
				continue
			}
			if _, ok := out[mm[1]]; !ok {
				t.Errorf("%s removes %q, which no seed migration creates", m, mm[1])
				continue
			}
			delete(out, mm[1])
			removed++
		}
		if removed == 0 {
			t.Errorf("%s is listed as removing permissions but no removed id was parsed", m)
		}
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

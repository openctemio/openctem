package postgres

import (
	"context"
	"sort"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// The built-in roles are defined twice: seeded by migrations (the grants that
// enforcement reads) and listed in permission.SystemRoles (what the role
// templates, the generated authorization matrix and the token fallback read).
// This pins the two together: a migration that changes a system role's
// grants without the Go list, or the reverse, fails here.
// Requires DATABASE_URL.
func TestSystemRolePermissions_MatchSeed(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, `
		SELECT r.id::text, r.slug, r.has_full_data_access, COALESCE(rp.permission_id, '')
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		WHERE r.is_system AND r.tenant_id IS NULL`)
	if err != nil {
		t.Fatalf("query system roles: %v", err)
	}
	defer func() { _ = rows.Close() }()

	type seeded struct {
		slug     string
		fullData bool
		perms    map[string]bool
	}
	db2go := map[string]*seeded{}
	for rows.Next() {
		var id, slug, perm string
		var full bool
		if err := rows.Scan(&id, &slug, &full, &perm); err != nil {
			t.Fatalf("scan: %v", err)
		}
		s := db2go[id]
		if s == nil {
			s = &seeded{slug: slug, fullData: full, perms: map[string]bool{}}
			db2go[id] = s
		}
		if perm != "" {
			s.perms[perm] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	want := permission.SystemRoles()
	if len(db2go) != len(want) {
		t.Errorf("the database seeds %d system roles, permission.SystemRoles lists %d", len(db2go), len(want))
	}
	for _, r := range want {
		s, ok := db2go[r.ID]
		if !ok {
			t.Errorf("system role %s (%s) is not seeded", r.Slug, r.ID)
			continue
		}
		if s.slug != r.Slug || s.fullData != r.HasFullDataAccess {
			t.Errorf("system role %s: seeded slug %q full data %v, Go says %q %v", r.ID, s.slug, s.fullData, r.Slug, r.HasFullDataAccess)
		}
		goPerms := map[string]bool{}
		for _, p := range r.Permissions {
			goPerms[string(p)] = true
		}
		var onlyDB, onlyGo []string
		for p := range s.perms {
			if !goPerms[p] {
				onlyDB = append(onlyDB, p)
			}
		}
		for p := range goPerms {
			if !s.perms[p] {
				onlyGo = append(onlyGo, p)
			}
		}
		sort.Strings(onlyDB)
		sort.Strings(onlyGo)
		if len(onlyDB)+len(onlyGo) > 0 {
			t.Errorf("system role %s: seeded but not in permission.SystemRoles %v; in permission.SystemRoles but not seeded %v", r.Slug, onlyDB, onlyGo)
		}
	}
}

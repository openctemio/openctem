package rawrole

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

const (
	scanDir       = "../../../internal"
	allowlistFile = "allowlist.txt"
)

func TestViolates(t *testing.T) {
	bad := []string{
		`SELECT 1 FROM tenant_members tm WHERE tm.role IN ('owner', 'admin')`,
		`SELECT count(*) FROM tenant_members WHERE user_id = $1 AND role = 'owner'`,
		`SELECT m.role FROM tenant_members m WHERE m.tenant_id = $1`,
		`SELECT 1 FROM tenant_members WHERE role NOT IN ('viewer')`,
		`SELECT COALESCE(ver.role, m.role) FROM tenant_members m LEFT JOIN v_user_effective_role ver ON true`,
	}
	for _, s := range bad {
		if !Violates(s) {
			t.Errorf("want a violation: %s", s)
		}
	}
	good := []string{
		`SELECT 1 FROM tenant_members m JOIN v_user_effective_role ver ON ver.user_id = m.user_id WHERE ver.role IN ('owner','admin')`,
		`UPDATE tenant_members SET role = $1 WHERE id = $2`,
		`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1,$2,$3,$4)`,
		`SELECT 1 FROM remediation_task_members tm WHERE tm.role = 'primary'`,
		`SELECT 1 FROM group_members gm WHERE gm.role = 'owner'`,
		`SELECT 1 FROM tenant_members tm JOIN remediation_task_members m ON true WHERE m.role = 'primary'`,
		`INSERT INTO tenant_members (id, role) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id, role = EXCLUDED.role`,
	}
	for _, s := range good {
		if Violates(s) {
			t.Errorf("want no violation: %s", s)
		}
	}
}

func loadAllowlist(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(allowlistFile)
	if err != nil {
		t.Fatalf("open %s: %v", allowlistFile, err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, reason, _ := strings.Cut(line, " ")
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s:%d: %q has no reason", allowlistFile, n, key)
		}
		if _, dup := out[key]; dup {
			t.Errorf("%s:%d: duplicate entry %q", allowlistFile, n, key)
		}
		out[key] = strings.TrimSpace(reason)
	}
	return out
}

// TestNoRawMembershipRoleReads fails on a SQL literal that decides from the
// raw tenant_members.role label and is not allowlisted, and on an allowlist
// entry that no longer matches anything (the list only shrinks).
func TestNoRawMembershipRoleReads(t *testing.T) {
	findings, err := Scan(scanDir)
	if err != nil {
		t.Fatal(err)
	}
	allow := loadAllowlist(t)
	seen := map[string]bool{}
	var bad []string
	for _, f := range findings {
		seen[f.Key()] = true
		if _, ok := allow[f.Key()]; ok {
			continue
		}
		bad = append(bad, fmt.Sprintf("%s:%d %s:\n    %s", f.File, f.Line, f.Func, f.SQL))
	}
	if len(bad) > 0 {
		t.Errorf("%d SQL literal(s) read the raw tenant_members.role label.\n"+
			"Join v_user_effective_role (ver.role) instead: it is the role the gates use. A query that must read\n"+
			"the label itself (the membership routes, the ownership transfer, a display column) goes in\n"+
			"tools/lint/rawrole/allowlist.txt as `path:Func  reason`.\n\n%s", len(bad), strings.Join(bad, "\n"))
	}
	var stale []string
	for k := range allow {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("stale %s entries (fixed or gone; delete the line):\n  %s", allowlistFile, strings.Join(stale, "\n  "))
	}
}

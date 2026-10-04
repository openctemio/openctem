package tenantsql

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

const (
	repoDir       = "../../../internal/infra/postgres"
	handlerDir    = "../../../internal/infra/http/handler"
	tablesFile    = "tenant_tables.txt"
	allowlistFile = "allowlist.txt"
)

// platformSuffixes mark a method as deliberately cross-tenant. The name is the
// reviewable marker, so such a method needs no allowlist entry; it may not be
// called from an HTTP handler (TestHandlersDoNotCallPlatformMethods).
var platformSuffixes = []string{"Unscoped", "ForPlatform"}

func isPlatformMethod(fn string) bool {
	m := fn
	if i := strings.LastIndex(fn, "."); i >= 0 {
		m = fn[i+1:]
	}
	for _, s := range platformSuffixes {
		if strings.HasSuffix(m, s) || strings.Contains(m, s+"In") {
			return true
		}
	}
	return false
}

// loadAllowlist reads "file:Func:table  reason" lines. Every entry needs a
// reason.
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
		reason = strings.TrimSpace(reason)
		if reason == "" {
			t.Errorf("%s:%d: %q has no reason", allowlistFile, n, key)
		}
		if _, dup := out[key]; dup {
			t.Errorf("%s:%d: duplicate entry %q", allowlistFile, n, key)
		}
		out[key] = reason
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestNoNewTenantlessStatements fails when a repository statement reads or
// writes a tenant-scoped row by id alone and is neither allowlisted nor in a
// method named ...Unscoped / ...ForPlatform. It also fails on stale allowlist
// entries, so the list only shrinks.
func TestNoNewTenantlessStatements(t *testing.T) {
	tables, err := LoadTenantTables(tablesFile)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(repoDir, tables)
	if err != nil {
		t.Fatal(err)
	}
	allow := loadAllowlist(t)
	seen := map[string]bool{}
	var bad []string
	for _, f := range findings {
		seen[f.Key()] = true
		if isPlatformMethod(f.Func) {
			continue
		}
		if _, ok := allow[f.Key()]; ok {
			continue
		}
		bad = append(bad, fmt.Sprintf("%s:%d %s on %s:\n    %s", f.File, f.Line, f.Func, f.Table, f.SQL))
	}
	if len(bad) > 0 {
		t.Errorf("%d repository statement(s) select/update/delete a tenant-scoped row by id with no tenant_id predicate.\n"+
			"Add `AND tenant_id = $n` and thread the tenant from the authenticated context. A caller that is\n"+
			"legitimately cross-tenant (a platform job or controller) gets its own method named ...ForPlatform or\n"+
			"...Unscoped, used only by that caller. See tools/lint/tenantsql/README.md.\n\n%s",
			len(bad), strings.Join(bad, "\n"))
	}
	var stale []string
	for k := range allow {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("stale %s entries (the statement is fixed or gone; delete the line):\n  %s",
			allowlistFile, strings.Join(stale, "\n  "))
	}
}

// reCallPlatform matches a call of a ...ForPlatform / ...Unscoped method.
var reCallPlatform = regexp.MustCompile(`\.\w+(?:ForPlatform|Unscoped)(?:In\w*)?\(`)

// TestHandlersDoNotCallPlatformMethods: an HTTP handler always acts for a
// tenant, so it never calls a cross-tenant repository method.
func TestHandlersDoNotCallPlatformMethods(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(handlerDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no handler files under %s", handlerDir)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if reCallPlatform.MatchString(line) {
				t.Errorf("%s:%d calls a cross-tenant method from an HTTP handler: %s",
					filepath.Base(f), i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestTenantTablesMatchSchema keeps tenant_tables.txt equal to the base
// tables with a tenant_id column in the migrated schema. It needs a database;
// TENANTSQL_UPDATE=1 rewrites the file.
func TestTenantTablesMatchSchema(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, `
		SELECT c.table_name
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id'
		  AND t.table_type = 'BASE TABLE'
		ORDER BY c.table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var live []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		live = append(live, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TENANTSQL_UPDATE") == "1" {
		body := "# Base tables with a tenant_id column. Generated: TENANTSQL_UPDATE=1 go test ./tools/lint/tenantsql -run TestTenantTablesMatchSchema\n" +
			strings.Join(live, "\n") + "\n"
		if err := os.WriteFile(tablesFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := LoadTenantTables(tablesFile)
	if err != nil {
		t.Fatal(err)
	}
	var missing, extra []string
	got := map[string]bool{}
	for _, n := range live {
		got[n] = true
		if !want[n] {
			missing = append(missing, n)
		}
	}
	for n := range want {
		if !got[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(extra)
	if len(missing)+len(extra) > 0 {
		t.Fatalf("%s drifted from the schema (regenerate with TENANTSQL_UPDATE=1):\n  missing: %v\n  no longer tenant-scoped: %v",
			tablesFile, missing, extra)
	}
}

func TestTenantless(t *testing.T) {
	tables := map[string]bool{"scans": true, "integrations": true, "assets": true}
	cases := []struct {
		sql  string
		want []string
	}{
		{"DELETE FROM scans WHERE id = $1", []string{"scans"}},
		{"DELETE FROM scans WHERE tenant_id = $1 AND id = $2", nil},
		{"DELETE FROM scans WHERE id = $1 AND tenant_id = $2", nil},
		{"SELECT id, tenant_id, name FROM integrations WHERE id = $1", []string{"integrations"}},
		{"UPDATE assets SET name = $2 WHERE id = ANY($1)", []string{"assets"}},
		{"UPDATE assets a SET name = $2 WHERE a.id = $1", []string{"assets"}},
		{"SELECT 1 FROM scans s JOIN assets a ON a.tenant_id = s.tenant_id WHERE s.id = $1", nil},
		{"SELECT * FROM audit_logs WHERE tenant_id IS NULL AND id = $1", nil},
		{"SELECT * FROM tools WHERE id = $1", nil},      // not tenant-scoped
		{"INSERT INTO scans (id) VALUES ($1)", nil},     // not a by-id read/write
		{"SELECT * FROM scans WHERE scan_id = $1", nil}, // a foreign key, not the pk
		{"SELECT * FROM scans WHERE name = $1 AND id = $2", []string{"scans"}},
	}
	for _, c := range cases {
		got := tenantless(c.sql, tables)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("tenantless(%q) = %v, want %v", c.sql, got, c.want)
		}
	}
}

// TestScanFoldsQueryConstruction checks the evaluator on the shapes the
// repositories use: literals, package constants, receiver helpers, +=, Sprintf.
func TestScanFoldsQueryConstruction(t *testing.T) {
	dir := t.TempDir()
	src := `package p

import "fmt"

const base = "SELECT id FROM scans"

type R struct{}

func (r *R) selectQuery() string { return "SELECT id, tenant_id FROM scans" }

func (r *R) A() { exec(base + " WHERE id = $1") }
func (r *R) B() { q := r.selectQuery(); q += " WHERE id = $1"; exec(q) }
func (r *R) C() { exec(fmt.Sprintf("DELETE FROM %s WHERE id = $1", "scans")) }
func (r *R) D() { exec(r.selectQuery() + " WHERE tenant_id = $1 AND id = $2") }
func (r *R) DeleteForPlatform() { exec("DELETE FROM scans WHERE id = $1") }

func exec(string) {}
`
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := Scan(dir, map[string]bool{"scans": true})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.Func)
	}
	want := "R.A,R.B,R.C,R.DeleteForPlatform"
	if strings.Join(got, ",") != want {
		t.Fatalf("Scan found %v, want %s", got, want)
	}
	if !isPlatformMethod("R.DeleteForPlatform") || isPlatformMethod("R.Delete") {
		t.Fatal("isPlatformMethod misclassified")
	}
}

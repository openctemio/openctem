package unit

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// A data migration that keeps rows "for its down migration" creates a backup,
// ledger or archive table. Such tables outlive the migration by years unless
// something forces the drop: migration 001481 removed twelve of them. This
// test walks the migration chain and fails when one of these tables is still
// there at the end of it, unless ledgerTableAllowlist covers it with an expiry
// date. When the date passes the test fails again, so the drop migration
// has to be written.
//
// A table counts as a ledger when its name has a backup, ledger, archive or
// legacy word, a pre_<migration> suffix, or ends in a migration number.
var ledgerTableName = regexp.MustCompile(`(^|_)(backup|backups|ledger|archive|legacy)(_|$)|_pre_[0-9]{4,}|_[0-9]{4,}$`)

// ledgerTableAllowlist: table -> the date (YYYY-MM-DD) by which a migration
// must drop it, with the reason it is kept until then. Keep entries short-lived.
var ledgerTableAllowlist = map[string]struct{ expires, reason string }{}

var (
	sqlLineComment = regexp.MustCompile(`--[^\n]*`)
	createTableRe  = regexp.MustCompile(`(?i)\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?`)
	renameTableRe  = regexp.MustCompile(`(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?\s+rename\s+to\s+"?([a-z_][a-z0-9_]*)"?`)
	dropTableRe    = regexp.MustCompile(`(?i)\bdrop\s+table\s+(?:if\s+exists\s+)?([a-z0-9_.,"\s]+?)(?:\s+cascade|\s+restrict)?\s*;`)
	tempTableRe    = regexp.MustCompile(`(?i)\bcreate\s+(?:local\s+|global\s+)?temp(?:orary)?\s+table`)
)

// ledgerTablesAfterChain replays CREATE / RENAME / DROP TABLE over the up
// migrations in version order and returns the ledger-named tables left.
func ledgerTablesAfterChain(t *testing.T, dir string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations in %s (%v)", dir, err)
	}
	sort.Strings(files)         // zero-padded versions sort in order
	live := map[string]string{} // table -> migration that created it
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		applyLedgerStatements(string(b), filepath.Base(f), live)
	}
	return live
}

func applyLedgerStatements(sqlText, file string, live map[string]string) {
	s := sqlLineComment.ReplaceAllString(sqlText, "")
	type ev struct {
		pos        int
		op         string
		name, into string
	}
	var evs []ev
	for _, m := range createTableRe.FindAllStringSubmatchIndex(s, -1) {
		// CREATE TEMP TABLE never outlives the session.
		if tempTableRe.MatchString(s[m[0]:m[1]]) {
			continue
		}
		evs = append(evs, ev{m[0], "create", strings.ToLower(s[m[2]:m[3]]), ""})
	}
	for _, m := range renameTableRe.FindAllStringSubmatchIndex(s, -1) {
		evs = append(evs, ev{m[0], "rename", strings.ToLower(s[m[2]:m[3]]), strings.ToLower(s[m[4]:m[5]])})
	}
	for _, m := range dropTableRe.FindAllStringSubmatchIndex(s, -1) {
		for _, n := range strings.Split(s[m[2]:m[3]], ",") {
			n = strings.Trim(strings.TrimSpace(n), `"`)
			n = strings.TrimPrefix(strings.ToLower(n), "public.")
			if n != "" {
				evs = append(evs, ev{m[0], "drop", n, ""})
			}
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].pos < evs[j].pos })
	for _, e := range evs {
		switch e.op {
		case "create":
			if ledgerTableName.MatchString(e.name) {
				live[e.name] = file
			}
		case "rename":
			created, ok := live[e.name]
			delete(live, e.name)
			if ledgerTableName.MatchString(e.into) {
				if !ok {
					created = file
				}
				live[e.into] = created
			}
		case "drop":
			delete(live, e.name)
		}
	}
}

func TestMigrationLedgerTablesAreDropped(t *testing.T) {
	live := ledgerTablesAfterChain(t, "../../migrations")
	today := time.Now().UTC().Format("2006-01-02")
	for name, file := range live {
		entry, ok := ledgerTableAllowlist[name]
		switch {
		case !ok:
			t.Errorf("%s (created by %s) is a backup/ledger/archive table that no later migration drops. "+
				"Drop it in a migration once the forward step is final, or add it to ledgerTableAllowlist with an expiry date.", name, file)
		case entry.expires == "" || entry.reason == "":
			t.Errorf("ledgerTableAllowlist[%s] needs both an expiry date and a reason", name)
		case entry.expires < today:
			t.Errorf("ledgerTableAllowlist[%s] expired on %s (%s): write the migration that drops it", name, entry.expires, entry.reason)
		}
	}
	for name := range ledgerTableAllowlist {
		if _, ok := live[name]; !ok {
			t.Errorf("ledgerTableAllowlist[%s]: no migration leaves this table behind any more; remove the entry", name)
		}
	}
}

// The parser behind the guard: what counts as created, renamed and dropped.
func TestLedgerStatementParsing(t *testing.T) {
	cases := []struct {
		name, sql string
		want      []string
	}{
		{"created and kept", `CREATE TABLE IF NOT EXISTS public.findings_backup_001500 AS SELECT * FROM findings;`, []string{"findings_backup_001500"}},
		{"created then dropped", "CREATE TABLE x_ledger (id int);\n-- later\nDROP TABLE IF EXISTS x_ledger;", nil},
		{"dropped in a list", `CREATE TABLE a_archive (id int); CREATE TABLE b_pre_001500 (id int); DROP TABLE a_archive, public.b_pre_001500 CASCADE;`, nil},
		{"temp table ignored", `CREATE TEMP TABLE scratch_backup_001500 (id int);`, nil},
		{"renamed to a ledger name", `CREATE TABLE plain (id int); ALTER TABLE plain RENAME TO plain_legacy;`, []string{"plain_legacy"}},
		{"renamed away from a ledger name", `CREATE TABLE old_legacy (id int); ALTER TABLE old_legacy RENAME TO current_things;`, nil},
		{"comment mentions are not statements", "-- CREATE TABLE ghost_backup_001500\nSELECT 1;", nil},
		{"ordinary table", `CREATE TABLE automations (id int);`, nil},
	}
	for _, c := range cases {
		live := map[string]string{}
		applyLedgerStatements(c.sql, "000001_x.up.sql", live)
		var got []string
		for n := range live {
			got = append(got, n)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: left %v, want %v", c.name, got, c.want)
		}
	}
	for _, n := range []string{"access_control_removed_archive", "asset_types_legacy_removed", "easm_ct_rekey_001018", "asset_properties_pre_001185", "technique_applicability_rekey_ledger"} {
		if !ledgerTableName.MatchString(n) {
			t.Errorf("%s should count as a ledger table name", n)
		}
	}
	for _, n := range []string{"assets", "asset_identity_backfill", "finding_rekey_runs", "audit_chain_rebaselines", "scan_workflow_versions"} {
		if ledgerTableName.MatchString(n) {
			t.Errorf("%s should not count as a ledger table name", n)
		}
	}
}

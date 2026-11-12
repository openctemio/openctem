package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// No table carries two indexes with the same keys, operator classes, sort
// options, predicate and expressions: every write would maintain both. Partition
// children are skipped (they mirror their parent's definitions).
func TestNoDuplicateIndexes_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "dup_index", "../../../migrations")
	rows, err := db.Query(`
SELECT i.indrelid::regclass::text, string_agg(i.indexrelid::regclass::text, ', ' ORDER BY i.indexrelid::regclass::text)
FROM pg_index i
JOIN pg_class c ON c.oid = i.indrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND NOT c.relispartition
GROUP BY i.indrelid, i.indkey::text, i.indclass::text, i.indoption::text,
         COALESCE(pg_get_expr(i.indpred, i.indrelid), ''), COALESCE(pg_get_expr(i.indexprs, i.indrelid), '')
HAVING count(*) > 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var dups []string
	for rows.Next() {
		var tbl, idx string
		if err := rows.Scan(&tbl, &idx); err != nil {
			t.Fatal(err)
		}
		dups = append(dups, tbl+": "+idx)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(dups) > 0 {
		t.Fatalf("duplicate indexes (drop one of each):\n%s", strings.Join(dups, "\n"))
	}
}

// The three redundant unique indexes were dropped without losing the keys that
// referenced them: every foreign key to findings, groups and remediation
// campaigns still exists, is validated and binds to a surviving index.
func TestDropDuplicateUniqueIndexesKeepsForeignKeys_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "dup_unique", dir)
	var gone int
	if err := db.QueryRow(`SELECT count(*) FROM pg_class WHERE relname IN
		('uq_findings_tenant_id_id','uq_groups_tenant_id_id','uq_remediation_campaigns_tenant_id_id',
		 'idx_findings_tenant_id_pk','idx_integrations_tenant_id_pk','idx_asset_change_events_tenant')`).Scan(&gone); err != nil {
		t.Fatal(err)
	}
	if gone != 0 {
		t.Fatalf("%d duplicate indexes still exist", gone)
	}
	var n, invalid int
	if err := db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE NOT convalidated) FROM pg_constraint
		WHERE contype='f' AND conname IN ('fk_finding_definitions_finding','fk_finding_fingerprints_finding',
		 'fk_finding_decision_reviews_finding_tenant','fk_ticket_links_finding_tenant','fk_remediation_task_members_finding',
		 'fk_remediation_key_exclusions_finding','fk_bounty_programs_group','group_role_bindings_group_id_tenant_id_fkey',
		 'fk_remediation_tasks_assignee_group','fk_ticket_links_campaign_tenant','fk_remediation_tasks_campaign')`).Scan(&n, &invalid); err != nil {
		t.Fatal(err)
	}
	if n != 11 || invalid != 0 {
		t.Fatalf("foreign keys kept: found %d of 11, %d not validated", n, invalid)
	}
}

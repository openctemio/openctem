package routes

// The findings search box (q) over the real routes: it matches title, file
// path, rule id, CVE id (exact) and asset name, never the description (that
// is the opt-in description filter), and it runs inside the caller's data
// scope, so a search cannot reveal an out-of-scope finding's text.

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestFindingsSearch_FieldsAndScope(t *testing.T) {
	h := newGroupScopeHarness(t)
	// The random tail of a v7 id (its head is the clock, shared by the
	// fixtures), and digits only for the CVE ids.
	id := shared.NewID().String()
	tok := id[len(id)-10:]
	n := 100000 + rand.IntN(800000) //nolint:gosec // test fixture id, not security relevant
	fa, fb, fb2 := h.findingA.String(), h.findingB.String(), h.findingB2.String()
	cveA, cveB := fmt.Sprintf("CVE-2098-%d1", n), fmt.Sprintf("CVE-2098-%d2", n)
	h.exec(`UPDATE findings SET title = $2, file_path = $3, rule_id = $4, cve_id = $5, description = $6 WHERE id = $1`,
		fa, "srchA title "+tok, "src/srchA_"+tok+"/main.go", "rule.srchA."+tok, cveA, "srchA-desc-"+tok)
	h.exec(`UPDATE findings SET title = $2, file_path = $3, rule_id = $4, cve_ids = ARRAY[$5]::text[], description = $6 WHERE id = $1`,
		fb, "srchB title "+tok, "src/srchB_"+tok+"/main.go", "rule.srchB."+tok, cveB, "srchB-desc-"+tok)
	h.exec(`UPDATE assets SET name = $2 WHERE id = $1`, h.assetA.String(), "srchA-host-"+tok+".example.com")
	h.exec(`UPDATE assets SET name = $2 WHERE id = $1`, h.assetB.String(), "srchB-host-"+tok+".example.com")

	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	cases := []struct {
		name, q        string
		admin, memberA []string
	}{
		{"title", "srchA title " + tok, sorted(fa), sorted(fa)},
		{"file path", "srchB_" + tok + "/main", sorted(fb), nil},
		{"rule id", "rule.srchA." + tok, sorted(fa), sorted(fa)},
		{"cve exact, lower case, spaces", " " + strings.ToLower(cveA) + " ", sorted(fa), sorted(fa)},
		{"cve prefix is not a match", cveA[:12], nil, nil},
		{"cve in cve_ids", cveB, sorted(fb), nil},
		// Every finding on the asset (FB2 is on B1 too).
		{"asset name", "srchB-host-" + tok, sorted(fb, fb2), nil},
		{"both titles", "title " + tok, sorted(fa, fb), sorted(fa)},
		{"description is not searched", "srchA-desc-" + tok, nil, nil},
		{"like metacharacters are literal", "srch%" + tok, nil, nil},
	}
	for _, c := range cases {
		for _, who := range []struct {
			caller flCaller
			want   []string
		}{{admin, c.admin}, {memberA, c.memberA}} {
			ids, total, _ := h.listIDs(t, who.caller, "state=all&q="+url.QueryEscape(c.q))
			if !slices.Equal(ids, who.want) || total != int64(len(who.want)) {
				t.Errorf("%s: %s q=%q = %v (total %d), want %v", c.name, who.caller.name, c.q, ids, total, who.want)
			}
		}
	}

	// The description is opt-in, and scoped too.
	for _, who := range []struct {
		caller flCaller
		want   []string
	}{{admin, sorted(fb)}, {memberA, nil}} {
		ids, _, _ := h.listIDs(t, who.caller, "state=all&description_contains="+url.QueryEscape("srchB-desc-"+tok))
		if !slices.Equal(ids, who.want) {
			t.Errorf("description_contains: %s = %v, want %v", who.caller.name, ids, who.want)
		}
	}
}

// The trigram indexes make "column ILIKE '%text%'" indexable, so the planner
// can use them when the table is large (seq scan disabled to prove it on a
// small test table).
func TestFindingsSearch_TrigramIndexesUsable(t *testing.T) {
	h := newGroupScopeHarness(t)
	ctx := context.Background()
	conn, err := h.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SET enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, "RESET enable_seqscan") }()
	for query, index := range map[string]string{
		"SELECT id FROM findings WHERE title ILIKE '%abcdef%'":     "idx_findings_title_trgm",
		"SELECT id FROM findings WHERE file_path ILIKE '%abcdef%'": "idx_findings_file_path_trgm",
		"SELECT id FROM findings WHERE rule_id ILIKE '%abcdef%'":   "idx_findings_rule_id_trgm",
		"SELECT id FROM assets WHERE name ILIKE '%abcdef%'":        "idx_assets_name_trgm",
	} {
		plan := explainPlan(ctx, t, conn, query)
		if !strings.Contains(plan, index) {
			t.Errorf("%s does not use %s:\n%s", query, index, plan)
		}
	}
}

func explainPlan(ctx context.Context, t *testing.T, conn *sql.Conn, query string) string {
	t.Helper()
	rows, err := conn.QueryContext(ctx, "EXPLAIN "+query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return plan.String()
}

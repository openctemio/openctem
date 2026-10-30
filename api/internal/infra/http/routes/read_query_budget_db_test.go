package routes

// Read query budget: the hot list, stats and dashboard reads over the real
// routes (data-scope harness), with every SQL statement counted. Two rules:
//
//  1. A read sends the same number of statements whatever the data size: the
//     counts are taken, the tenant grows (more assets, repositories, groups
//     members and findings), and the counts must not change. An N+1 (a query
//     per row of the page) fails here.
//  2. A read sends at most its entry in testdata/read_budget.json. A change
//     that needs more statements rewrites the file with
//     `go test ./internal/infra/http/routes/ -run TestReadQueryBudget -update-read-budgets`
//     and explains it in the pull request.
//
// The owner and a data-scoped member both run every read, so the scoped
// paths are held to the same rules.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb/sqlcount"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var updateReadBudgets = flag.Bool("update-read-budgets", false, "rewrite testdata/read_budget.json with the measured counts")

const readBudgetFile = "testdata/read_budget.json"

// readBudgetRoutes are the reads every console page load or list view makes.
var readBudgetRoutes = []string{ //nolint:gochecknoglobals // test table
	"/api/v1/findings?per_page=20",
	"/api/v1/findings?per_page=20&q=host",
	"/api/v1/findings?per_page=20&severity=critical,high&sort=-severity",
	"/api/v1/findings/stats",
	"/api/v1/assets?per_page=20",
	"/api/v1/assets?per_page=20&search=host",
	"/api/v1/assets/stats",
	"/api/v1/asset-groups",
	"/api/v1/dashboard/stats",
	"/api/v1/attack-surface/stats",
	"/api/v1/notifications/unread-count",
}

type readBudget struct {
	Comment string         `json:"_comment"`
	Reads   map[string]int `json:"reads"`
}

func TestReadQueryBudget(t *testing.T) {
	counter := &sqlcount.Counter{}
	prev := dsOpenDB
	dsOpenDB = func(dsn string) (*sql.DB, error) { return sqlcount.Open(dsn, counter) }
	h := newDSHarness(t)
	dsOpenDB = prev

	callers := []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"memberA", h.memberA, false}}

	measure := func() map[string]int {
		out := map[string]int{}
		for _, c := range callers {
			for _, path := range readBudgetRoutes {
				counter.Settle(50*time.Millisecond, 2*time.Second)
				counter.Reset()
				status, body := h.do(c.user, c.admin, http.MethodGet, path, nil)
				if status != http.StatusOK {
					t.Fatalf("%s GET %s = %d: %.300s", c.name, path, status, body)
				}
				out[c.name+" "+path] = counter.Settle(50*time.Millisecond, 2*time.Second).Statements
			}
		}
		return out
	}

	measure() // warm the per-process caches (permissions, data scope) so both counts see them warm
	small := measure()
	growTenant(h, 40)
	large := measure()

	keys := make([]string, 0, len(small))
	for k := range small {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if large[k] != small[k] {
			t.Errorf("%s: %d statements with the seed, %d after the tenant grew: a query per row (N+1)", k, small[k], large[k])
		}
	}

	if *updateReadBudgets {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(readBudget{
			Comment: "Most SQL statements one read may send (TestReadQueryBudget). Rewrite with -update-read-budgets and explain the change.",
			Reads:   large,
		}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(readBudgetFile, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(readBudgetFile)
	if err != nil {
		t.Fatalf("%v (run with -update-read-budgets to create it)", err)
	}
	var budget readBudget
	if err := json.Unmarshal(raw, &budget); err != nil {
		t.Fatalf("%s: %v", readBudgetFile, err)
	}
	for _, k := range keys {
		want, ok := budget.Reads[k]
		switch {
		case !ok:
			t.Errorf("%s: no budget in %s (run with -update-read-budgets)", k, readBudgetFile)
		case large[k] > want:
			t.Errorf("%s: %d SQL statements, budget %d. If intended, run with -update-read-budgets and explain it in the pull request", k, large[k], want)
		case large[k] < want:
			t.Logf("%s: %d statements, under the budget of %d; -update-read-budgets locks the saving in", k, large[k], want)
		}
	}
	for k := range budget.Reads {
		if _, ok := large[k]; !ok {
			t.Errorf("%s: the budget names a read this test no longer makes", k)
		}
	}
}

// growTenant adds n repository assets (with their repository rows), n group
// members and three findings per asset to the harness tenant.
func growTenant(h *dsHarness, n int) {
	t := h.tenant.String()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality)
		SELECT gen_random_uuid(), $1, 'grow-host-' || g || '.example.com', 'repository', 'public', 'medium'
		FROM generate_series(1, $2::int) g`, t, n)
	h.exec(`INSERT INTO asset_repositories (asset_id, full_name)
		SELECT id, 'example/' || name FROM assets WHERE tenant_id = $1 AND name LIKE 'grow-host-%'`, t)
	h.exec(`INSERT INTO asset_group_members (asset_group_id, asset_id)
		SELECT $2, id FROM assets WHERE tenant_id = $1 AND name LIKE 'grow-host-%'`, t, h.group.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, title)
		SELECT gen_random_uuid(), $1, a.id, 'sast', 'grow-tool', 'grow', (ARRAY['critical','high','medium'])[k], 'grow-' || a.id || '-' || k, 'new',
		       'grow host finding ' || k
		FROM assets a CROSS JOIN generate_series(1, 3) k WHERE a.tenant_id = $1 AND a.name LIKE 'grow-host-%'`, t)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
		SELECT $2, $1, id, 'secondary' FROM assets WHERE tenant_id = $1 AND name LIKE 'grow-host-%' LIMIT $3`, t, h.memberA.String(), n/2)
}

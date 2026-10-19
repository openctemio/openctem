package integration

// The campaign-scope notice migration lists, per tenant, the open campaigns
// that track nothing once scope must name what is fixed (severity, source,
// status or search alone), and changes no row. Found by name, so the merge
// queue may renumber it.

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigrationCampaignScopeNotice_ListsUnscopedCampaigns(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		testdb.Skipf(t, "DATABASE_URL not set")
	}
	// The notice reads the legacy finding_filter column, which the contract
	// migration drops: use a private database with that migration reverted so
	// the shared one is never altered.
	const dir = "../../migrations"
	priv := testdb.PrivateDatabase(t, "csn", dir)
	drop := testdb.MigrationVersion(t, dir, "remediation_campaigns_drop_finding_filter")
	testdb.Migrate(t, priv, dir, drop, drop, true)
	var dbName string
	if err := priv.QueryRow(`SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	pu, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pu.Path = "/" + dbName
	files, err := filepath.Glob("../../migrations/*_campaign_scope_unscoped_notice.up.sql")
	if err != nil || len(files) != 1 {
		t.Fatalf("migration file: %v %v", files, err)
	}
	up, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var notices []string
	base, err := pq.NewConnector(pu.String())
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(pq.ConnectorWithNoticeHandler(base, func(n *pq.Error) {
		mu.Lock()
		defer mu.Unlock()
		notices = append(notices, n.Message)
	}))
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	tenant := shared.NewID().String()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant, "csn-"+tenant)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant) })
	ids := map[string]string{}
	for name, row := range map[string][2]string{
		"csn-severity-only": {"active", `{"severities": ["critical"]}`},
		"csn-source-search": {"draft", `{"source": "sast", "search": "x"}`},
		"csn-tool":          {"active", `{"severities": ["high"], "tool_name": "trivy"}`},
		"csn-key":           {"active", `{"remediation_key": "sol:sast:abc"}`},
		"csn-empty":         {"active", `{}`},
		"csn-done":          {"completed", `{"severities": ["low"]}`},
	} {
		id := shared.NewID().String()
		ids[name] = id
		exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter) VALUES ($1, $2, $3, $4, $5::jsonb)`,
			id, tenant, name, row[0], row[1])
	}
	var before string
	if err := db.QueryRowContext(ctx, `SELECT string_agg(id::text || finding_filter::text || version::text, ',' ORDER BY id) FROM remediation_campaigns WHERE tenant_id = $1`, tenant).Scan(&before); err != nil {
		t.Fatal(err)
	}

	exec(string(up))

	mu.Lock()
	all := strings.Join(notices, "\n")
	mu.Unlock()
	for _, name := range []string{"csn-severity-only", "csn-source-search"} {
		if !strings.Contains(all, ids[name]) {
			t.Errorf("%s not reported:\n%s", name, all)
		}
	}
	for _, name := range []string{"csn-tool", "csn-key", "csn-empty", "csn-done"} {
		if strings.Contains(all, ids[name]) {
			t.Errorf("%s reported but it has scope, is empty or is closed:\n%s", name, all)
		}
	}
	var after string
	if err := db.QueryRowContext(ctx, `SELECT string_agg(id::text || finding_filter::text || version::text, ',' ORDER BY id) FROM remediation_campaigns WHERE tenant_id = $1`, tenant).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Error("the notice migration changed campaign rows")
	}
}

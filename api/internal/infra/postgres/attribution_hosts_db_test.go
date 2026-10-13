package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Children follow their host (research/117 F1) on the real schema: links by
// relationship and by the host part of the name, only within the tenant and
// only to exactly one host; the host's state cascades to its automatic
// children only; a person's decision on a child breaks the link; the review
// queue lists the host with its children counted. Requires DATABASE_URL.
func TestAttributionChildrenFollowHost(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAttributionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	asset := func(tid shared.ID, name, typ string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
			id, tid.String(), name, typ); err != nil {
			t.Fatal(err)
		}
		return id
	}
	pending := func(tid shared.ID, id string) {
		t.Helper()
		if err := repo.SaveAutomatic(ctx, tid, id, attribution.Decision{State: attribution.StateNeedsReview, Confidence: 60,
			Reason: attribution.RuleScanDiscovered}); err != nil {
			t.Fatal(err)
		}
	}
	edge := func(tid shared.ID, src, dst, typ string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
			VALUES ($1, $2, $3, $4)`, tid.String(), src, dst, typ); err != nil {
			t.Fatal(err)
		}
	}
	rec := func(tid shared.ID, id string) attribution.Record {
		t.Helper()
		m, err := repo.Records(ctx, tid, []string{id})
		if err != nil {
			t.Fatal(err)
		}
		return m[id]
	}

	// An address with a service (exposes) and a certificate the service
	// served (serves_certificate): the certificate follows the address.
	ip := asset(tenant, "198.51.100.9", "ip_address")
	svc := asset(tenant, "198.51.100.9:443", "service")
	cert := asset(tenant, "ab12cd34", "certificate")
	edge(tenant, ip, svc, "exposes")
	edge(tenant, svc, cert, "serves_certificate")
	// A name with a URL and a service found by name only.
	host := asset(tenant, "app.example.com", "subdomain")
	app := asset(tenant, "https://app.example.com/login", "application")
	byName := asset(tenant, "app.example.com:8443:tcp", "service")
	// Not linked: a certificate two hosts served; a child a person decided;
	// a service whose only host by name is another tenant's.
	ip2 := asset(tenant, "198.51.100.10", "ip_address")
	svc2 := asset(tenant, "198.51.100.10:443", "service")
	edge(tenant, ip2, svc2, "exposes")
	shared2 := asset(tenant, "ef56", "certificate")
	edge(tenant, svc, shared2, "serves_certificate")
	edge(tenant, svc2, shared2, "serves_certificate")
	decidedChild := asset(tenant, "198.51.100.9:22", "service")
	edge(tenant, ip, decidedChild, "exposes")
	orphan := asset(tenant, "203.0.113.50:80", "service")
	foreignHost := asset(other, "203.0.113.50", "ip_address")
	for _, id := range []string{ip, svc, cert, host, app, byName, ip2, svc2, shared2, decidedChild, orphan} {
		pending(tenant, id)
	}
	pending(other, foreignHost)
	if _, err := repo.SaveDecision(ctx, tenant, decidedChild, attribution.StateNeedsReview, ""); err != nil {
		t.Fatal(err)
	}

	n, err := repo.LinkChildren(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 { // svc, cert, app, byName, svc2
		t.Fatalf("linked %d, want 5", n)
	}
	want := map[string]string{svc: ip, cert: ip, app: host, byName: host, svc2: ip2, shared2: "", decidedChild: "", orphan: "", ip: "", host: ""}
	for id, h := range want {
		if got := rec(tenant, id).FollowsHost; got != h {
			t.Errorf("%s follows %q, want %q", id, got, h)
		}
	}
	// Idempotent.
	if n, err := repo.LinkChildren(ctx, tenant); err != nil || n != 0 {
		t.Fatalf("second link: %d %v", n, err)
	}
	// Another tenant: nothing of tenant A is linked by B's run.
	if n, err := repo.LinkChildren(ctx, other); err != nil || n != 0 {
		t.Fatalf("other tenant link: %d %v", n, err)
	}

	// The queue lists hosts with their children counted, never the children.
	page, err := repo.ListForReview(ctx, tenant, nil, easm.ReviewQuery{
		States: []attribution.State{attribution.StateNeedsReview, attribution.StateCandidate}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]easm.ReviewItem{}
	for _, it := range page.Items {
		rows[it.AssetID] = it
	}
	for _, id := range []string{svc, cert, app, byName, svc2} {
		if _, listed := rows[id]; listed {
			t.Errorf("child %s listed as its own row", id)
		}
	}
	if c := rows[ip].Children; c["service"] != 1 || c["certificate"] != 1 {
		t.Errorf("ip children = %v", c)
	}
	if c := rows[host].Children; c["service"] != 1 || c["application"] != 1 {
		t.Errorf("host children = %v", c)
	}
	// ip, host, ip2, the certificate two hosts served, the child a person
	// decided and the service with no host of this tenant.
	if page.Total != 6 || len(page.Items) != 6 {
		t.Fatalf("queue rows %d, total %d, want 6", len(page.Items), page.Total)
	}

	// A person's decision on the host cascades to its automatic children.
	if _, err := repo.SaveDecisions(ctx, tenant, []string{ip}, attribution.StateConfirmed, ""); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{svc, cert} {
		r := rec(tenant, id)
		if r.State != attribution.StateConfirmed || r.HumanDecided {
			t.Fatalf("%s after host confirm: %+v", id, r)
		}
	}
	if r := rec(tenant, decidedChild); r.State != attribution.StateNeedsReview {
		t.Fatalf("a person's decision on a child was overridden: %+v", r)
	}
	if _, err := repo.SaveDecision(ctx, tenant, ip, attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}
	if r := rec(tenant, svc); r.State != attribution.StateRejected {
		t.Fatalf("service after host rejection: %+v", r)
	}
	// Automation never moves a child on its own while it follows a host.
	if err := repo.SaveAutomatic(ctx, tenant, svc, attribution.Decision{State: attribution.StateConfirmed, Confidence: 99}); err != nil {
		t.Fatal(err)
	}
	if r := rec(tenant, svc); r.State != attribution.StateRejected {
		t.Fatalf("automation moved a follower: %+v", r)
	}
	// An automatic change of the host (the scope join) cascades too.
	if err := repo.SaveAutomatic(ctx, tenant, host, attribution.Decision{State: attribution.StateConfirmed, Confidence: 99,
		Reason: attribution.RuleMatchesScopeTarget}); err != nil {
		t.Fatal(err)
	}
	if r := rec(tenant, app); r.State != attribution.StateConfirmed {
		t.Fatalf("url after host joined scope: %+v", r)
	}
	// A person's decision on a child breaks its link.
	if _, err := repo.SaveDecision(ctx, tenant, app, attribution.StateMonitorOnly, ""); err != nil {
		t.Fatal(err)
	}
	if r := rec(tenant, app); r.FollowsHost != "" || r.State != attribution.StateMonitorOnly {
		t.Fatalf("decided child: %+v", r)
	}
	if _, err := repo.SaveDecision(ctx, tenant, host, attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}
	if r := rec(tenant, app); r.State != attribution.StateMonitorOnly {
		t.Fatalf("host cascade overrode a person's decision on the child: %+v", r)
	}
	// Tenant B never sees or changes tenant A's links.
	if r := rec(other, svc); r.State != "" {
		t.Fatalf("tenant B read tenant A's record: %+v", r)
	}
	// Deleting the host clears the link (FK ON DELETE SET NULL).
	if _, err := db.ExecContext(ctx, `DELETE FROM assets WHERE id = $1`, ip2); err != nil {
		t.Fatal(err)
	}
	var follows sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT follows_host_id FROM asset_attributions WHERE asset_id = $1`, svc2).Scan(&follows); err != nil {
		t.Fatal(err)
	}
	if follows.Valid {
		t.Fatalf("link survived the host's deletion: %v", follows.String)
	}
}

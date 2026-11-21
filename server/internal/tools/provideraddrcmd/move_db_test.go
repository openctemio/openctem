package provideraddrcmd

// The provider-address move against a migrated database
// (docs/architecture/provider-address-move.md): every organization gets its own
// rows, history is folded (never moved backwards), name services and
// certificates move to their names with their findings untouched, plain
// addresses are archived and every other one kept, a dry run counts exactly
// what the apply does, a second apply changes nothing, an interrupted apply
// resumes, a dataset change is a new pass (A3, A4), and a restore puts
// everything back. DB-gated: DATABASE_URL must point at a migrated *_test
// database.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/app/provideraddr"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/internal/tools/toolaudit"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	pa "github.com/openctemio/openctem/server/pkg/domain/provideraddr"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type moveEnv struct {
	t    *testing.T
	ctx  context.Context
	db   *sql.DB
	repo *postgres.ProviderAddressMoveRepository
	svc  *provideraddr.Service
}

func newMoveEnv(t *testing.T) *moveEnv {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "database unreachable: %v", err)
	}
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewProviderAddressMoveRepository(pdb)
	auditRepo := postgres.NewAuditRepository(pdb)
	auditor := func(ctx context.Context, tenantID shared.ID, action audit.Action, counts map[string]int) error {
		return toolaudit.Record(ctx, auditRepo, toolaudit.Event{TenantID: tenantID, Action: action,
			ResourceType: audit.ResourceTypeAsset, Actor: actor, RunID: "test", Counts: counts})
	}
	return &moveEnv{t: t, ctx: context.Background(), db: db, repo: repo,
		svc: provideraddr.NewService(repo, auditor, postgres.NewDashboardFactsRepository(pdb))}
}

func (e *moveEnv) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.ExecContext(e.ctx, q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

func (e *moveEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRowContext(e.ctx, q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *moveEnv) str(q string, args ...any) string {
	e.t.Helper()
	var s sql.NullString
	if err := e.db.QueryRowContext(e.ctx, q, args...).Scan(&s); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return s.String
}

func (e *moveEnv) tenant() shared.ID {
	e.t.Helper()
	id := shared.NewID()
	e.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'provider-move', $2)`, id.String(), "provider-move-"+id.String())
	e.t.Cleanup(func() {
		_, _ = e.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

func (e *moveEnv) asset(tenant shared.ID, name, typ string, props string) string {
	e.t.Helper()
	id := shared.NewID().String()
	if props == "" {
		props = "{}"
	}
	e.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status, properties) VALUES ($1, $2, $3, $4, 'active', $5)`,
		id, tenant.String(), name, typ, props)
	return id
}

func (e *moveEnv) edge(tenant shared.ID, src, dst, typ, method string, created time.Time, verified *time.Time) string {
	e.t.Helper()
	id := shared.NewID().String()
	e.exec(`INSERT INTO asset_relationships (id, tenant_id, source_asset_id, target_asset_id, relationship_type, discovery_method,
		created_at, last_verified) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, tenant.String(), src, dst, typ, method, created, verified)
	return id
}

func (e *moveEnv) attribution(tenant shared.ID, asset, state, reason string, human bool) {
	e.t.Helper()
	var at any
	if human {
		at = time.Now().UTC()
	}
	e.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, reason, decided_at) VALUES ($1, $2, $3, 80, $4, $5)`,
		asset, tenant.String(), state, reason, at)
}

func (e *moveEnv) finding(tenant shared.ID, asset, fp, severity string) string {
	e.t.Helper()
	id := shared.NewID().String()
	e.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
		sla_started_at, sla_deadline) VALUES ($1, $2, $3, 'dast', 'nuclei', 'm', $4, $5, 'new', now() - interval '1 day', now() + interval '6 days')`,
		id, tenant.String(), asset, severity, fp)
	return id
}

// snapshot is a digest of everything the move may change for a tenant.
func (e *moveEnv) snapshot(tenant shared.ID) string {
	e.t.Helper()
	return e.str(`SELECT md5(concat_ws('|',
		(SELECT string_agg(id::text || status, ',' ORDER BY id) FROM assets WHERE tenant_id = $1),
		(SELECT string_agg(id::text || source_asset_id::text || target_asset_id::text || relationship_type, ',' ORDER BY id) FROM asset_relationships WHERE tenant_id = $1),
		(SELECT string_agg(asset_id::text || source_name || element || first_seen::text || last_seen::text || coalesce(removed_at::text, '-'), ',' ORDER BY asset_id, source_name, element) FROM asset_attribute_set_elements WHERE tenant_id = $1),
		(SELECT string_agg(asset_id::text || state || reason, ',' ORDER BY asset_id) FROM asset_attributions WHERE tenant_id = $1)))`, tenant.String())
}

// scopeDigest is a digest of the tenant's scope entries and exclusions: the
// move never writes them.
func (e *moveEnv) scopeDigest(tenant shared.ID) string {
	e.t.Helper()
	return e.str(`SELECT md5(concat_ws('|',
		(SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM scope_targets s WHERE tenant_id = $1),
		(SELECT string_agg(to_jsonb(x)::text, ',' ORDER BY id) FROM scope_exclusions x WHERE tenant_id = $1)))`, tenant.String())
}

// findingDigest covers every field of a finding the move must never touch.
func (e *moveEnv) findingDigest(tenant shared.ID) string {
	e.t.Helper()
	return e.str(`SELECT md5(string_agg(concat_ws(':', id, asset_id, status, row_version, fingerprint, sla_started_at, sla_deadline,
		first_detected_at, severity), ',' ORDER BY id)) FROM findings WHERE tenant_id = $1`, tenant.String())
}

// sharedAddrs returns n distinct addresses of the built-in dataset's
// shared ranges, from as many providers as it has (never hard-coded, so the
// test follows dataset refreshes).
func sharedAddrs(t *testing.T, n int) []string {
	t.Helper()
	c := edgeaddr.Default()
	var out []string
	for _, p := range c.SharedFrontEndPrefixes() {
		if !p.Addr().Is4() || p.Bits() > 28 {
			continue
		}
		a := p.Addr().Next()
		for range 4 {
			if _, ok := c.SharedFrontEnd(a.String()); ok {
				out = append(out, a.String())
				if len(out) == n {
					return out
				}
			}
			a = a.Next()
		}
	}
	t.Fatalf("dataset holds fewer than %d usable shared addresses", n)
	return nil
}

// fixture is one organization's provider addresses.
type fixture struct {
	tenant                                     shared.ID
	mail, app, cert                            string
	plain, nameSvc, addrSvc, entry, person     string
	tagged, running, dedicated, holderOnly     string
	svc, portSvc, critical, info, resolveEdge  string
	plainAddr, nameSvcAddr, entryAddr, runAddr string
	t0, t1, t2, t3                             time.Time
}

// seed builds the same provider estate in a tenant.
func (e *moveEnv) seed(addrs []string) *fixture {
	e.t.Helper()
	f := &fixture{tenant: e.tenant()}
	tn := f.tenant
	f.t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f.t1, f.t2, f.t3 = f.t0.Add(24*time.Hour), f.t0.Add(48*time.Hour), f.t0.Add(96*time.Hour)
	f.mail = e.asset(tn, "mail.example.com", "subdomain", "")
	f.app = e.asset(tn, "app.example.com", "subdomain", "")
	f.cert = e.asset(tn, "cert-"+shared.NewID().String()[:8], "certificate", `{"sans": ["app.example.com"]}`)
	f.plainAddr, f.nameSvcAddr, f.entryAddr, f.runAddr = addrs[0], addrs[1], addrs[3], addrs[6]

	// Plain: a name-to-address link only; the name's dnsx history already
	// holds the address with a later window.
	f.plain = e.asset(tn, addrs[0], "ip_address", "")
	e.attribution(tn, f.plain, "discovered", "dns_resolution", false)
	f.resolveEdge = e.edge(tn, f.mail, f.plain, "resolves_to", "automatic", f.t0, &f.t2)
	e.exec(`INSERT INTO asset_attribute_set_elements (tenant_id, asset_id, attribute, source_kind, source_name, element, first_seen, last_seen)
		VALUES ($1, $2, 'ip_addresses', 'scan', 'dnsx', $3, $4, $5)`, tn.String(), f.mail, addrs[0], f.t1, f.t3)
	// An exclusion on it stays as it is.
	e.exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status) VALUES ($1, 'ip_address', $2, 'test', 'active')`,
		tn.String(), addrs[0])

	// A name service (https://app.example.com) and a certificate for the
	// name hang off a provider address.
	f.nameSvc = e.asset(tn, addrs[1], "ip_address", "")
	e.edge(tn, f.app, f.nameSvc, "resolves_to", "automatic", f.t0, nil)
	f.svc = e.asset(tn, "https://app.example.com", "service", "")
	e.edge(tn, f.nameSvc, f.svc, "exposes", "inferred", f.t0, nil)
	e.edge(tn, f.nameSvc, f.cert, "serves_certificate", "automatic", f.t0, nil)
	f.critical = e.finding(tn, f.svc, "fp-critical-"+tn.String(), "critical")

	// Services named by the address itself: kept; discovered -> dependency.
	f.addrSvc = e.asset(tn, addrs[2], "ip_address", "")
	e.attribution(tn, f.addrSvc, "discovered", "dns_resolution", false)
	f.portSvc = e.asset(tn, addrs[2]+":993:tcp", "service", "")
	e.edge(tn, f.addrSvc, f.portSvc, "exposes", "automatic", f.t0, nil)
	f.info = e.finding(tn, f.portSvc, "fp-info-"+tn.String(), "info")

	// An exact scope entry covers it: kept, its confirmed record stays.
	f.entry = e.asset(tn, addrs[3], "ip_address", "")
	e.attribution(tn, f.entry, "confirmed", "matches_scope_target", false)
	e.edge(tn, f.mail, f.entry, "resolves_to", "automatic", f.t0, nil)
	e.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, origin, status) VALUES ($1, 'ip_address', $2, 'import', 'active')`,
		tn.String(), addrs[3])

	// A person's decision: kept and never relabelled.
	f.person = e.asset(tn, addrs[4], "ip_address", "")
	e.attribution(tn, f.person, "confirmed", "", true)

	// A tag: kept.
	f.tagged = e.asset(tn, addrs[5], "ip_address", "")
	e.exec(`UPDATE assets SET tags = '{keep}' WHERE tenant_id = $1 AND id = $2`, tn.String(), f.tagged)
	e.edge(tn, f.mail, f.tagged, "resolves_to", "automatic", f.t0, nil)

	// The target of a running scan: skipped this pass.
	f.running = e.asset(tn, addrs[6], "ip_address", "")
	e.edge(tn, f.mail, f.running, "resolves_to", "automatic", f.t0, nil)
	e.exec(`INSERT INTO scan_runs (tenant_id, kind, trigger_type, status, asset_id) VALUES ($1, 'system', 'system', 'running', $2)`,
		tn.String(), f.running)

	// Dedicated addresses are never touched: one outside every list, one
	// whose network holder is a provider but outside the provider's lists.
	f.dedicated = e.asset(tn, "192.0.2.10", "ip_address", "")
	e.edge(tn, f.mail, f.dedicated, "resolves_to", "automatic", f.t0, nil)
	f.holderOnly = e.asset(tn, "198.51.100.7", "ip_address", `{"asn_org": "Cloudflare, Inc."}`)
	e.edge(tn, f.app, f.holderOnly, "resolves_to", "automatic", f.t0, nil)
	return f
}

func (e *moveEnv) run(tenant shared.ID, opts provideraddr.Options) *provideraddr.Report {
	e.t.Helper()
	rep, err := e.svc.Run(e.ctx, tenant, opts)
	if err != nil {
		e.t.Fatalf("run %s: %v", opts.Mode, err)
	}
	return rep
}

func withoutVolatile(c pa.Counts) pa.Counts {
	out := maps.Clone(c)
	delete(out, pa.CountReclassified)
	return out
}

// TestProviderJob_EndToEnd covers the whole move on one organization while
// a second organization with the same names and addresses is untouched.
func TestProviderJob_EndToEnd_DB(t *testing.T) {
	e := newMoveEnv(t)
	addrs := sharedAddrs(t, 7)
	a, b := e.seed(addrs), e.seed(addrs)
	tn := a.tenant
	beforeA, beforeB := e.snapshot(tn), e.snapshot(b.tenant)
	scopeA, findingsA := e.scopeDigest(tn), e.findingDigest(tn)
	opts := provideraddr.Options{BatchSize: 3}

	// Dry run: changes nothing, writes one row with the counts.
	dry := e.run(tn, opts)
	if e.snapshot(tn) != beforeA || e.count(`SELECT count(*) FROM provider_address_move_items WHERE tenant_id = $1`, tn.String()) != 0 {
		t.Fatal("the dry run changed something")
	}
	if e.count(`SELECT count(*) FROM provider_address_moves WHERE tenant_id = $1 AND mode = 'dry_run' AND state = 'done'`, tn.String()) != 1 {
		t.Fatal("the dry run row is missing")
	}
	c := dry.Counts
	want := map[string]int{
		pa.CountAddresses: 7, pa.CountEdgesFolded: 4, pa.CountEdgesNotInHistory: 3, pa.CountServicesRelinked: 1,
		pa.CountCertificatesRelinked: 1, pa.CountAddressServices: 1, pa.CountAddressServiceFindings: 1,
		pa.CountArchived: 2, pa.CountKept: 4, pa.CountSkippedActiveRun: 1, pa.SeverityKey("critical"): 1,
		pa.CountCardEntriesExact: 1, pa.CountFindingStatusChanges: 0, pa.CountInventoryRemoved: 2,
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("dry run %s = %d, want %d (all: %v)", k, c[k], v, c)
		}
	}
	if c[pa.CountInventoryAfterExpected] != c[pa.CountInventoryBefore]-2 {
		t.Errorf("inventory before %d after %d", c[pa.CountInventoryBefore], c[pa.CountInventoryAfterExpected])
	}

	// Apply: the same counts.
	applied := e.run(tn, provideraddr.Options{Mode: pa.ModeApply, BatchSize: 3})
	if !maps.Equal(withoutVolatile(applied.Counts), withoutVolatile(dry.Counts)) {
		t.Fatalf("apply counts differ from the dry run:\n apply %v\n dry   %v", applied.Counts, dry.Counts)
	}
	if !applied.Completed || !applied.NoticeSent {
		t.Fatalf("apply report = %+v", applied)
	}

	// Plain: archived as a provider address, its edge folded as history only.
	if s := e.str(`SELECT status FROM assets WHERE id = $1`, a.plain); s != "archived" {
		t.Errorf("plain status = %s", s)
	}
	if s := e.str(`SELECT state || '/' || reason FROM asset_attributions WHERE asset_id = $1`, a.plain); s != "dependency/provider_shared_front_end" {
		t.Errorf("plain attribution = %s", s)
	}
	var first, last, removed time.Time
	if err := e.db.QueryRowContext(e.ctx, `SELECT first_seen, last_seen, removed_at FROM asset_attribute_set_elements
		WHERE tenant_id = $1 AND asset_id = $2 AND source_name = 'migrated_resolves_to' AND element = $3`, tn.String(), a.mail, a.plainAddr).
		Scan(&first, &last, &removed); err != nil {
		t.Fatalf("folded row: %v", err)
	}
	if !first.Equal(a.t0) || !last.Equal(a.t2) || !removed.Equal(a.t2) {
		t.Errorf("folded row = %s %s %s, want %s %s %s", first, last, removed, a.t0, a.t2, a.t2)
	}
	if n := e.count(`SELECT count(*) FROM asset_attribute_set_elements WHERE tenant_id = $1 AND asset_id = $2 AND source_name = 'dnsx'
		AND first_seen = $3 AND last_seen = $4 AND removed_at IS NULL`, tn.String(), a.mail, a.t1, a.t3); n != 1 {
		t.Error("the dnsx history row changed")
	}
	if n := e.count(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND relationship_type = 'resolves_to'
		AND target_asset_id = ANY($2::uuid[])`, tn.String(), "{"+strings.Join([]string{a.plain, a.nameSvc, a.entry, a.tagged}, ",")+"}"); n != 0 {
		t.Errorf("%d name-to-provider-address edges left", n)
	}
	if s := e.str(`SELECT reason FROM asset_state_history
		WHERE tenant_id = $1 AND asset_id = $2 AND change_type = 'status_changed'`, tn.String(), a.plain); s != "provider_address" {
		t.Errorf("status history reason = %q", s)
	}

	// Name service and certificate moved to the name; the address archived.
	if n := e.count(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND source_asset_id = $2 AND target_asset_id = $3
		AND relationship_type = 'exposes' AND discovery_method = 'inferred' AND description = $4`, tn.String(), a.app, a.svc, pa.RelinkDescription); n != 1 {
		t.Error("the name service was not relinked to its name")
	}
	if n := e.count(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND source_asset_id = $2 AND target_asset_id = $3
		AND relationship_type = 'serves_certificate'`, tn.String(), a.app, a.cert); n != 1 {
		t.Error("the certificate was not relinked to its name")
	}
	if n := e.count(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND source_asset_id = $2`, tn.String(), a.nameSvc); n != 0 {
		t.Errorf("%d edges left on the name-service address", n)
	}
	if s := e.str(`SELECT status FROM assets WHERE id = $1`, a.nameSvc); s != "archived" {
		t.Errorf("name-service address status = %s", s)
	}

	// Kept addresses.
	if s := e.str(`SELECT status || '/' || state FROM assets a JOIN asset_attributions t ON t.asset_id = a.id WHERE a.id = $1`, a.addrSvc); s != "active/dependency" {
		t.Errorf("address-service address = %s", s)
	}
	if s := e.str(`SELECT status || '/' || state FROM assets a JOIN asset_attributions t ON t.asset_id = a.id WHERE a.id = $1`, a.entry); s != "active/confirmed" {
		t.Errorf("entry-covered address = %s", s)
	}
	if s := e.str(`SELECT status || '/' || state || '/' || (decided_at IS NOT NULL)::text FROM assets a JOIN asset_attributions t ON t.asset_id = a.id WHERE a.id = $1`, a.person); s != "active/confirmed/true" {
		t.Errorf("person-decided address = %s", s)
	}
	for _, id := range []string{a.tagged, a.running, a.dedicated, a.holderOnly} {
		if s := e.str(`SELECT status FROM assets WHERE id = $1`, id); s != "active" {
			t.Errorf("address %s status = %s", id, s)
		}
	}
	if n := e.count(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND target_asset_id = ANY($2::uuid[])`,
		tn.String(), "{"+a.running+","+a.dedicated+","+a.holderOnly+"}"); n != 3 {
		t.Errorf("edges of skipped/dedicated addresses = %d, want 3", n)
	}
	if s := e.str(`SELECT outcome FROM provider_address_move_items WHERE tenant_id = $1 AND asset_id = $2`, tn.String(), a.running); s != pa.OutcomeSkippedActiveRun {
		t.Errorf("running address outcome = %q", s)
	}

	// Findings, scope and the other organization are untouched.
	if e.findingDigest(tn) != findingsA {
		t.Error("a finding changed")
	}
	if e.scopeDigest(tn) != scopeA {
		t.Error("scope entries or exclusions changed")
	}
	if e.snapshot(b.tenant) != beforeB || e.count(`SELECT count(*) FROM provider_address_moves WHERE tenant_id = $1`, b.tenant.String()) != 0 {
		t.Error("the other organization changed")
	}

	// Audit, dashboard request, one notice.
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'asset.provider_addresses_moved'`, tn.String()); n != 1 {
		t.Errorf("%d audit entries", n)
	}
	if n := e.count(`SELECT count(*) FROM dash_fact_status WHERE tenant_id = $1 AND rebuild_requested_at IS NOT NULL`, tn.String()); n != 1 {
		t.Error("no dashboard refresh requested")
	}
	if n := e.count(`SELECT count(*) FROM notifications WHERE tenant_id = $1 AND notification_type = 'system_alert'`, tn.String()); n != 1 {
		t.Errorf("%d notices", n)
	}
	var notice pa.Notice
	if err := json.Unmarshal([]byte(e.str(`SELECT notice::text FROM provider_address_moves WHERE tenant_id = $1 AND notice IS NOT NULL`, tn.String())), &notice); err != nil {
		t.Fatal(err)
	}
	if notice.Addresses != 5 || notice.Names != 2 || notice.Entries != 1 || notice.Vi == "" {
		t.Errorf("notice = %+v", notice)
	}

	// A second apply changes nothing and journals nothing new (the running
	// address is still skipped while its run is running).
	afterApply := e.snapshot(tn)
	items := e.count(`SELECT count(*) FROM provider_address_move_items WHERE tenant_id = $1`, tn.String())
	again := e.run(tn, provideraddr.Options{Mode: pa.ModeApply, BatchSize: 3})
	if e.snapshot(tn) != afterApply || again.Counts[pa.CountArchived] != 0 || again.Counts[pa.CountEdgesFolded] != 0 {
		t.Fatalf("second apply changed something: %v", again.Counts)
	}
	if n := e.count(`SELECT count(*) FROM provider_address_move_items WHERE tenant_id = $1`, tn.String()); n != items+1 {
		t.Fatalf("second apply journaled %d items, want only the skipped one again", n-items)
	}
	if n := e.count(`SELECT count(*) FROM notifications WHERE tenant_id = $1 AND notification_type = 'system_alert'`, tn.String()); n != 1 {
		t.Errorf("notice sent again: %d", n)
	}

	// The run ends: the next pass handles the skipped address.
	e.exec(`UPDATE scan_runs SET status = 'completed' WHERE tenant_id = $1`, tn.String())
	third := e.run(tn, provideraddr.Options{Mode: pa.ModeApply, BatchSize: 3})
	if third.Counts[pa.CountArchived] != 1 || e.str(`SELECT status FROM assets WHERE id = $1`, a.running) != "archived" {
		t.Fatalf("next pass after the run ended: %v", third.Counts)
	}

	// Restore puts back exactly what the applies changed.
	restored := e.run(tn, provideraddr.Options{Mode: pa.ModeRestore, BatchSize: 2})
	if restored.Counts[pa.CountChanged] != 0 || restored.Counts[pa.CountRestored] == 0 {
		t.Fatalf("restore = %v", restored.Counts)
	}
	e.exec(`UPDATE scan_runs SET status = 'running' WHERE tenant_id = $1`, tn.String()) // the snapshot ignores runs; keep state equal anyway
	if got := e.snapshot(tn); got != beforeA {
		t.Fatal("restore did not bring the organization back to where it was")
	}
	if e.findingDigest(tn) != findingsA {
		t.Error("a finding changed during the restore")
	}
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'asset.provider_addresses_restored'`, tn.String()); n != 1 {
		t.Errorf("%d restore audit entries", n)
	}
}

// A restore leaves an address a person changed since the apply as it is.
func TestProviderJob_RestoreLeavesChangedAddress_DB(t *testing.T) {
	e := newMoveEnv(t)
	addrs := sharedAddrs(t, 7)
	f := e.seed(addrs)
	e.run(f.tenant, provideraddr.Options{Mode: pa.ModeApply})
	e.exec(`UPDATE assets SET status = 'active' WHERE id = $1`, f.plain) // a person brought it back
	rep := e.run(f.tenant, provideraddr.Options{Mode: pa.ModeRestore})
	if rep.Counts[pa.CountChanged] != 1 {
		t.Fatalf("restore = %v", rep.Counts)
	}
	if s := e.str(`SELECT outcome FROM provider_address_move_items WHERE tenant_id = $1 AND asset_id = $2 AND action = 'archive'`, f.tenant.String(), f.plain); s != pa.OutcomeChanged {
		t.Errorf("outcome = %s", s)
	}
	if n := e.count(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND target_asset_id = $2`, f.tenant.String(), f.plain); n != 0 {
		t.Error("a changed address got its edges back")
	}
}

// An apply stopped after two batches resumes where it stopped and ends
// where an uninterrupted apply ends; the dry run counts what both do.
func TestProviderJob_ResumesAfterCrash_DB(t *testing.T) {
	e := newMoveEnv(t)
	addrs := sharedAddrs(t, 12)
	build := func() (shared.ID, string) {
		tn := e.tenant()
		name := e.asset(tn, "www.example.com", "subdomain", "")
		for _, ad := range addrs {
			id := e.asset(tn, ad, "ip_address", "")
			e.edge(tn, name, id, "resolves_to", "automatic", time.Now().Add(-time.Hour).UTC(), nil)
		}
		return tn, name
	}
	whole, _ := build()
	crashed, _ := build()
	dry := e.run(crashed, provideraddr.Options{BatchSize: 3})
	// The uninterrupted apply reads 5 assets per batch but changes at most 2
	// provider addresses per batch: batches cut short end the same way.
	full := e.run(whole, provideraddr.Options{Mode: pa.ModeApply, BatchSize: 5, MaxShared: 2})
	if full.Batches < 6 {
		t.Fatalf("batches = %d, want at least 6 with 2 provider addresses per batch", full.Batches)
	}

	part := e.run(crashed, provideraddr.Options{Mode: pa.ModeApply, BatchSize: 3, MaxBatches: 2})
	if part.Completed {
		t.Fatal("stopped run reports completed")
	}
	if n := e.count(`SELECT count(*) FROM provider_address_moves WHERE tenant_id = $1 AND mode = 'apply' AND state = 'running'`, crashed.String()); n != 1 {
		t.Fatal("the stopped run is not open")
	}
	rest := e.run(crashed, provideraddr.Options{Mode: pa.ModeApply, BatchSize: 3})
	if !rest.Resumed || !rest.Completed {
		t.Fatalf("resume = %+v", rest)
	}
	for _, tn := range []shared.ID{whole, crashed} {
		if n := e.count(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND status = 'archived'`, tn.String()); n != 12 {
			t.Errorf("archived %d, want 12", n)
		}
		if n := e.count(`SELECT count(*) FROM provider_address_move_items WHERE tenant_id = $1`, tn.String()); n != 12 {
			t.Errorf("journal %d, want 12", n)
		}
	}
	if !maps.Equal(withoutVolatile(rest.Counts), withoutVolatile(full.Counts)) || !maps.Equal(withoutVolatile(dry.Counts), withoutVolatile(full.Counts)) {
		t.Fatalf("counts differ:\n resumed %v\n full    %v\n dry     %v", rest.Counts, full.Counts, dry.Counts)
	}
}

// testDataset publishes documentation ranges, so dataset changes can be
// played without the real lists.
func testDataset(t *testing.T, version string, prefixes ...string) *edgeaddr.Classifier {
	t.Helper()
	c, err := edgeaddr.New(edgeaddr.Dataset{Version: version, Ranges: []edgeaddr.RangeEntry{
		{Provider: "Example CDN", Class: edgeaddr.Edge, Prefixes: prefixes}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A3: a dataset that newly lists a range makes the next pass move the
// addresses it now holds. A4: a dataset that withdraws a range restores the
// archived addresses (outcome reclassified, never confirmed). An address
// named in a non-canonical IPv6 form folds onto the canonical element.
func TestProviderJob_DatasetVersions_DB(t *testing.T) {
	e := newMoveEnv(t)
	tn := e.tenant()
	name := e.asset(tn, "edge.example.com", "subdomain", "")
	old := e.asset(tn, "198.51.100.9", "ip_address", "")
	e.attribution(tn, old, "confirmed", "matches_scope_target", false)
	e.edge(tn, name, old, "resolves_to", "automatic", time.Now().Add(-time.Hour).UTC(), nil)
	newly := e.asset(tn, "203.0.113.20", "ip_address", "")
	e.edge(tn, name, newly, "resolves_to", "automatic", time.Now().Add(-time.Hour).UTC(), nil)
	v6 := e.asset(tn, "2001:DB8:0:0::5", "ip_address", "")
	e.edge(tn, name, v6, "resolves_to", "automatic", time.Now().Add(-time.Hour).UTC(), nil)

	v1 := testDataset(t, "test-1", "198.51.100.0/24", "2001:db8::/32")
	rep := e.run(tn, provideraddr.Options{Mode: pa.ModeApply, Classifier: v1})
	if rep.Counts[pa.CountArchived] != 2 || e.str(`SELECT status FROM assets WHERE id = $1`, newly) != "active" {
		t.Fatalf("v1 = %v", rep.Counts)
	}
	if n := e.count(`SELECT count(*) FROM asset_attribute_set_elements WHERE tenant_id = $1 AND asset_id = $2 AND element = '2001:db8::5'
		AND source_name = 'migrated_resolves_to'`, tn.String(), name); n != 1 {
		t.Error("the non-canonical IPv6 name was not folded onto the canonical element")
	}

	v2 := testDataset(t, "test-2", "198.51.100.0/24", "2001:db8::/32", "203.0.113.0/24")
	rep = e.run(tn, provideraddr.Options{Mode: pa.ModeApply, Classifier: v2})
	if rep.Counts[pa.CountArchived] != 1 || rep.DatasetVersion != "test-2" || e.str(`SELECT status FROM assets WHERE id = $1`, newly) != "archived" {
		t.Fatalf("v2 = %v", rep.Counts)
	}

	// The dry run of v3 counts the withdrawn address without restoring it.
	v3 := testDataset(t, "test-3", "2001:db8::/32", "203.0.113.0/24")
	if dry := e.run(tn, provideraddr.Options{Classifier: v3}); dry.Counts[pa.CountReclassified] != 1 || e.str(`SELECT status FROM assets WHERE id = $1`, old) != "archived" {
		t.Fatalf("v3 dry run = %v", dry.Counts)
	}
	rep = e.run(tn, provideraddr.Options{Mode: pa.ModeApply, Classifier: v3})
	if rep.Counts[pa.CountReclassified] != 1 {
		t.Fatalf("v3 = %v", rep.Counts)
	}
	if s := e.str(`SELECT a.status || '/' || t.state FROM assets a JOIN asset_attributions t ON t.asset_id = a.id WHERE a.id = $1`, old); s != "active/discovered" {
		t.Errorf("withdrawn address = %s, want active/discovered (never confirmed by the move)", s)
	}
	if s := e.str(`SELECT outcome FROM provider_address_move_items WHERE tenant_id = $1 AND asset_id = $2`, tn.String(), old); s != pa.OutcomeReclassified {
		t.Errorf("outcome = %s", s)
	}
	if n := e.count(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND target_asset_id = $2`, tn.String(), old); n != 1 {
		t.Error("the withdrawn address did not get its edge back")
	}
}

// Every kind of reference that holds an address keeps it (table-driven over
// representative references of the asset merge list, plus tags, a child
// asset and a manual edge); history-only references do not.
func TestProviderJob_AnyPersonReferenceKeepsAddress_DB(t *testing.T) {
	e := newMoveEnv(t)
	cls := testDataset(t, "test-1", "198.51.100.0/24")
	cases := []struct {
		name string
		add  func(tn shared.ID, id string)
		kept bool
	}{
		{"finding", func(tn shared.ID, id string) { e.finding(tn, id, "fp-"+id, "low") }, true},
		{"asset_services", func(tn shared.ID, id string) {
			e.exec(`INSERT INTO asset_services (tenant_id, asset_id, port) VALUES ($1, $2, 443)`, tn.String(), id)
		}, true},
		{"asset_technologies", func(tn shared.ID, id string) {
			e.exec(`INSERT INTO asset_technologies (tenant_id, asset_id, name_key, name, first_seen, last_seen) VALUES ($1, $2, 'nginx', 'nginx', now(), now())`, tn.String(), id)
		}, true},
		{"tag", func(tn shared.ID, id string) { e.exec(`UPDATE assets SET tags = '{x}' WHERE id = $1`, id) }, true},
		{"child", func(tn shared.ID, id string) {
			c := e.asset(tn, "child-"+id, "service", "")
			e.exec(`UPDATE assets SET parent_id = $1 WHERE id = $2`, id, c)
		}, true},
		{"manual edge", func(tn shared.ID, id string) {
			o := e.asset(tn, "other-"+id, "host", "")
			e.edge(tn, o, id, "depends_on", "manual", time.Now().UTC(), nil)
		}, true},
		{"manual status", func(tn shared.ID, id string) {
			e.exec(`UPDATE assets SET manual_status_override = true WHERE id = $1`, id)
		}, true},
		{"history only", func(tn shared.ID, id string) {
			e.exec(`INSERT INTO asset_change_events (id, tenant_id, asset_id, at, attribute, source_kind, source_name, reason)
				VALUES ($1, $2, $3, now(), 'ip_addresses', 'scan', 'dnsx', 'newer_observation')`, shared.NewID().String(), tn.String(), id)
		}, false},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tn := e.tenant()
			name := e.asset(tn, "ref.example.com", "subdomain", "")
			id := e.asset(tn, fmt.Sprintf("198.51.100.%d", 20+i), "ip_address", "")
			e.edge(tn, name, id, "resolves_to", "automatic", time.Now().Add(-time.Hour).UTC(), nil)
			tc.add(tn, id)
			e.run(tn, provideraddr.Options{Mode: pa.ModeApply, Classifier: cls})
			status := e.str(`SELECT status FROM assets WHERE id = $1`, id)
			if tc.kept != (status == "active") {
				t.Errorf("%s: status %s, kept want %v", tc.name, status, tc.kept)
			}
		})
	}
	// Every reference of the merge list other than history keeps an address.
	refs := strings.Join(postgres.ProviderKeepRefs(), " ")
	for _, r := range []string{"findings.asset_id", "asset_owners.asset_id", "asset_group_members.asset_id", "business_service_assets.asset_id",
		"asset_access_grants.asset_id", "compensating_control_assets.asset_id", "threat_model_threats.target_asset_id",
		"bounty_program_target_assets.asset_id", "asset_program_links.asset_id", "web_watches.asset_id", "asset_software.asset_id"} {
		if !strings.Contains(refs, r) {
			t.Errorf("%s does not keep an address", r)
		}
	}
	for _, r := range []string{"asset_change_events.asset_id", "asset_coverage.asset_id", "scan_run_targets.asset_id", "asset_liveness.asset_id"} {
		if strings.Contains(refs, r) {
			t.Errorf("history reference %s keeps an address", r)
		}
	}
}

// Two runners on one organization: the advisory lock lets one batch through
// at a time and no item is journaled twice.
func TestProviderJob_ConcurrentReplicas_DB(t *testing.T) {
	e := newMoveEnv(t)
	cls := testDataset(t, "test-1", "198.51.100.0/24")
	tn := e.tenant()
	name := e.asset(tn, "busy.example.com", "subdomain", "")
	for i := range 40 {
		id := e.asset(tn, fmt.Sprintf("198.51.100.%d", 100+i), "ip_address", "")
		e.edge(tn, name, id, "resolves_to", "automatic", time.Now().Add(-time.Hour).UTC(), nil)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = e.svc.Run(e.ctx, tn, provideraddr.Options{Mode: pa.ModeApply, BatchSize: 2, Classifier: cls})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil && !errors.Is(err, pa.ErrBusy) && !errors.Is(err, pa.ErrNotRunning) {
			t.Fatalf("runner error: %v", err)
		}
	}
	// Finish whatever a busy runner left open.
	e.run(tn, provideraddr.Options{Mode: pa.ModeApply, BatchSize: 2, Classifier: cls})
	if n := e.count(`SELECT count(*) FROM provider_address_move_items WHERE tenant_id = $1`, tn.String()); n != 40 {
		t.Errorf("journal %d, want 40", n)
	}
	if n := e.count(`SELECT count(DISTINCT asset_id) FROM provider_address_move_items WHERE tenant_id = $1`, tn.String()); n != 40 {
		t.Errorf("distinct %d, want 40", n)
	}
}

// A batch whose writes change a finding's status is rolled back and the run
// is marked failed: the move never changes a finding.
func TestProviderJob_ZeroFindingStatusChanges_DB(t *testing.T) {
	e := newMoveEnv(t)
	cls := testDataset(t, "test-1", "198.51.100.0/24")
	tn := e.tenant()
	app := e.asset(tn, "zero.example.com", "subdomain", "")
	addr := e.asset(tn, "198.51.100.50", "ip_address", "")
	svc := e.asset(tn, "https://zero.example.com", "service", "")
	e.edge(tn, addr, svc, "exposes", "inferred", time.Now().UTC(), nil)
	e.finding(tn, svc, "fp-zero-"+tn.String(), "high")
	// A trigger that changes the finding when its edge is deleted, for this
	// organization only.
	// The trigger is DDL, which the app role may not run: the migrator owns
	// the schema, as in production.
	mig := testdb.OpenMigrator(t)
	fn := "test_pa_" + strings.ReplaceAll(tn.String()[:8], "-", "")
	if _, err := mig.ExecContext(e.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		UPDATE findings SET status = 'confirmed' WHERE tenant_id = '%s'; RETURN OLD; END $$`, fn, tn.String())); err != nil {
		t.Fatal(err)
	}
	if _, err := mig.ExecContext(e.ctx, fmt.Sprintf(`CREATE TRIGGER %s AFTER DELETE ON asset_relationships FOR EACH ROW WHEN (OLD.tenant_id = '%s') EXECUTE FUNCTION %s()`, fn, tn.String(), fn)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = mig.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON asset_relationships`, fn))
		_, _ = mig.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn))
	})
	before := e.findingDigest(tn)
	_, err := e.svc.Run(e.ctx, tn, provideraddr.Options{Mode: pa.ModeApply, Classifier: cls})
	if !errors.Is(err, pa.ErrFindingStatusChanged) {
		t.Fatalf("err = %v, want ErrFindingStatusChanged", err)
	}
	if e.findingDigest(tn) != before || e.str(`SELECT status FROM assets WHERE id = $1`, addr) != "active" {
		t.Fatal("the batch was not rolled back")
	}
	if n := e.count(`SELECT count(*) FROM provider_address_moves WHERE tenant_id = $1 AND state = 'failed'`, tn.String()); n != 1 {
		t.Error("the run is not marked failed")
	}
	_ = app
}

// A direct result on an address the move archived revives it; an address
// a person archived stays archived.
func TestProviderJob_ReviveOnlyMoveArchived_DB(t *testing.T) {
	e := newMoveEnv(t)
	cls := testDataset(t, "test-1", "198.51.100.0/24")
	tn := e.tenant()
	name := e.asset(tn, "rev.example.com", "subdomain", "")
	moved := e.asset(tn, "198.51.100.60", "ip_address", "")
	e.edge(tn, name, moved, "resolves_to", "automatic", time.Now().Add(-time.Hour).UTC(), nil)
	byPerson := e.asset(tn, "198.51.100.61", "ip_address", "")
	e.exec(`UPDATE assets SET status = 'archived' WHERE id = $1`, byPerson)
	e.run(tn, provideraddr.Options{Mode: pa.ModeApply, Classifier: cls})

	other := e.tenant()
	for _, c := range []struct {
		tenant shared.ID
		id     string
		want   bool
	}{{other, moved, false}, {tn, byPerson, false}, {tn, moved, true}, {tn, moved, false}} {
		id, _ := shared.IDFromString(c.id)
		got, err := e.repo.ReviveProviderAddress(e.ctx, c.tenant, id)
		if err != nil || got != c.want {
			t.Errorf("revive %s in %s = %v, %v; want %v", c.id, c.tenant, got, err, c.want)
		}
	}
	if s := e.str(`SELECT status FROM assets WHERE id = $1`, moved); s != "active" {
		t.Errorf("revived status = %s", s)
	}
	if s := e.str(`SELECT outcome FROM provider_address_move_items WHERE tenant_id = $1 AND asset_id = $2`, tn.String(), moved); s != pa.OutcomeRevived {
		t.Errorf("outcome = %s", s)
	}
	if s := e.str(`SELECT status FROM assets WHERE id = $1`, byPerson); s != "archived" {
		t.Errorf("person-archived status = %s", s)
	}
	// The next pass keeps a revived address.
	rep := e.run(tn, provideraddr.Options{Mode: pa.ModeApply, Classifier: cls})
	if rep.Counts[pa.AddressKey("Example CDN", pa.BucketRevived)] != 1 || e.str(`SELECT status FROM assets WHERE id = $1`, moved) != "active" {
		t.Errorf("next pass = %v", rep.Counts)
	}
}

// The plain-text report names every count category of the runbook.
func TestProviderJob_ReportFormat_DB(t *testing.T) {
	e := newMoveEnv(t)
	f := e.seed(sharedAddrs(t, 7))
	rep := e.run(f.tenant, provideraddr.Options{})
	out := provideraddr.Format(rep)
	for _, s := range []string{"dry run", "Addresses inside published shared ranges: 7", "folded", "Services moved", "findings on those services: critical 1",
		"Services named by the address", "Addresses archived: 2", "Skipped", "Scope entries for the scope card: 1 exact", "Inventory total", "Finding status changes: 0"} {
		if !strings.Contains(out, s) {
			t.Errorf("report misses %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "example.com") || strings.Contains(out, f.plainAddr) {
		t.Error("the report names an asset")
	}
}

// TestIngest_DirectResultOnArchivedProviderAddress_Revives: a scan report
// that names an address the move archived brings it back (active, still a
// dependency, journal outcome revived); the same report on an address a
// person archived leaves it archived.
func TestIngest_DirectResultOnArchivedProviderAddress_Revives_DB(t *testing.T) {
	e := newMoveEnv(t)
	cls := testDataset(t, "test-1", "198.51.100.0/24")
	tn := e.tenant()
	name := e.asset(tn, "ing.example.com", "subdomain", "")
	moved := e.asset(tn, "198.51.100.70", "ip_address", "")
	e.edge(tn, name, moved, "resolves_to", "automatic", time.Now().Add(-time.Hour).UTC(), nil)
	byPerson := e.asset(tn, "198.51.100.71", "ip_address", "")
	e.exec(`UPDATE assets SET status = 'archived', manual_status_override = true WHERE id = $1`, byPerson)
	e.run(tn, provideraddr.Options{Mode: pa.ModeApply, Classifier: cls})
	if s := e.str(`SELECT status FROM assets WHERE id = $1`, moved); s != "archived" {
		t.Fatalf("fixture: moved status = %s", s)
	}

	pdb := &postgres.DB{DB: e.db}
	log := logger.NewNop()
	svc := ingest.NewService(postgres.NewAssetRepository(pdb), postgres.NewFindingRepository(pdb),
		postgres.NewVulnerabilityRepository(pdb), postgres.NewComponentRepository(pdb),
		postgres.NewSensorRepository(pdb), postgres.NewBranchRepository(pdb), postgres.NewTenantRepository(pdb),
		postgres.NewAuditRepository(pdb), log)
	svc.SetProviderAddressReviver(e.repo)
	report := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "naabu"},
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()},
		Assets: []ctis.Asset{
			{ID: "a1", Type: ctis.AssetTypeIPAddress, Value: "198.51.100.70"},
			{ID: "a2", Type: ctis.AssetTypeIPAddress, Value: "198.51.100.71"},
		}}
	agt := &sensor.Sensor{TenantID: &tn, Status: sensor.SensorStatusActive}
	if _, err := svc.Ingest(e.ctx, agt, ingest.Input{Report: report}); err != nil {
		t.Fatal(err)
	}
	if s := e.str(`SELECT a.status || '/' || t.state FROM assets a JOIN asset_attributions t ON t.asset_id = a.id WHERE a.id = $1`, moved); s != "active/dependency" {
		t.Errorf("moved address after a direct result = %s, want active/dependency", s)
	}
	if s := e.str(`SELECT outcome FROM provider_address_move_items WHERE tenant_id = $1 AND asset_id = $2`, tn.String(), moved); s != pa.OutcomeRevived {
		t.Errorf("journal outcome = %s", s)
	}
	if s := e.str(`SELECT status FROM assets WHERE id = $1`, byPerson); s != "archived" {
		t.Errorf("person-archived address = %s, want archived", s)
	}
}

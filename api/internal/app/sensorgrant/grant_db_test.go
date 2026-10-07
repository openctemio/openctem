package sensorgrant_test

// Per-sensor grants against a migrated database (RFC-052 §5, threat model
// §6 rows 2, 11, 13, 14, 15, 16 and cross-tenant): the default grant of a new
// sensor, narrowing and widening by permission, compare-and-swap, tenant
// isolation, and enforcement on poll, claim by id, results without a job and
// heartbeat actions.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fixture struct {
	t      *testing.T
	db     *sql.DB
	pg     *postgres.DB
	grants *postgres.SensorGrantRepository
	svc    *sensorgrant.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	sqldb, err := sql.Open("postgres", url)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.Ping(); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	pg := &postgres.DB{DB: sqldb}
	grants := postgres.NewSensorGrantRepository(pg)
	svc := sensorgrant.NewService(grants, postgres.NewSensorRepository(pg), logger.NewNop())
	svc.SetZoneChecker(grants)
	return &fixture{t: t, db: sqldb, pg: pg, grants: grants, svc: svc}
}

func (f *fixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(context.Background(), q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

// org creates a tenant and an administrator user.
func (f *fixture) org() (tenantID, userID shared.ID) {
	f.t.Helper()
	tid, uid := shared.NewID(), shared.NewID()
	f.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'grants', $2)`, tid.String(), "grant-"+tid.String())
	f.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'grant admin')`, uid.String(), uid.String()+"@grant.test")
	f.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.db.ExecContext(ctx, `DELETE FROM commands WHERE tenant_id = $1`, tid.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM sensors WHERE tenant_id = $1`, tid.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM scan_zones WHERE tenant_id = $1`, tid.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
		_, _ = f.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, uid.String())
	})
	return tid, uid
}

// sensor inserts an online sensor that reported tools and capabilities
// (the trigger gives it the default grant).
func (f *fixture) sensor(tenantID shared.ID, tools []string, caps []string) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	f.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, api_key_hash, api_key_prefix,
		capabilities, execution_mode, max_concurrent_jobs, current_jobs, last_seen_at,
		reported_tool_names, reported_capabilities)
		VALUES ($1, $2, $3, 'worker', 'active', 'online', $4, $5, $7, 'daemon', 5, 0, NOW(), $6, $7)`,
		id.String(), tenantID.String(), "grant-sensor-"+id.String(), "hash-"+id.String(), id.String()[:8],
		pqArray(tools), pqArray(caps))
	return id
}

func pqArray(v []string) string {
	b, _ := json.Marshal(v)
	s := string(b)
	return "{" + s[1:len(s)-1] + "}"
}

func admin(tid, uid shared.ID) sensorgrant.Actor {
	return sensorgrant.Actor{TenantID: tid, UserID: uid, Email: "admin@grant.test", CanNarrow: true, CanWiden: true}
}

func narrowOnly(tid, uid shared.ID) sensorgrant.Actor {
	a := admin(tid, uid)
	a.CanWiden = false
	return a
}

// input copies g into an update input.
func input(g *sensordom.Grant) sensorgrant.UpdateInput {
	return sensorgrant.UpdateInput{Version: g.Version, TrustLevel: g.TrustLevel, JobTypes: g.JobTypes, ZoneIDs: g.ZoneIDs,
		Tools: g.Tools, Capabilities: g.Capabilities, TierCeiling: g.TierCeiling, TargetNetwork: g.TargetNetwork,
		TargetCIDRs: g.TargetCIDRs, TargetDomains: g.TargetDomains, AllowCredentials: g.AllowCredentials,
		AllowPushIngest: g.AllowPushIngest, RemoteActions: g.RemoteActions}
}

func TestGrant_DefaultAndChanges_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, uid := f.org()
	otherTenant, otherUser := f.org()
	sid := f.sensor(tid, []string{"nuclei"}, nil)

	// A new sensor starts with the narrowest default (trigger).
	g, err := f.svc.Get(ctx, tid, sid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if g.Profile != sensordom.ProfileInternalScanner || g.TrustLevel != sensordom.TrustNew || g.AllowCredentials ||
		g.AllowPushIngest || g.TierCeiling != sensordom.TierActive || len(g.RemoteActions) != 0 || g.Version != 1 {
		t.Fatalf("default grant: %+v", g)
	}

	// Cross-tenant: another organization reads and writes nothing.
	if _, err := f.svc.Get(ctx, otherTenant, sid); !errors.Is(err, sensorgrant.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := f.svc.Update(ctx, admin(otherTenant, otherUser), sid, input(g)); !errors.Is(err, sensorgrant.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}

	// Threat 16: a narrow-only administrator cannot promote or widen.
	promote := input(g)
	promote.TrustLevel = sensordom.TrustTrusted
	if _, err := f.svc.Update(ctx, narrowOnly(tid, uid), sid, promote); !errors.Is(err, sensorgrant.ErrWidenForbidden) {
		t.Fatalf("narrow-only promote: %v", err)
	}
	widen := input(g)
	widen.AllowPushIngest = true
	if _, err := f.svc.Update(ctx, narrowOnly(tid, uid), sid, widen); !errors.Is(err, sensorgrant.ErrWidenForbidden) {
		t.Fatalf("narrow-only widening: %v", err)
	}
	if _, err := f.svc.Update(ctx, sensorgrant.Actor{TenantID: tid, UserID: uid}, sid, input(g)); !errors.Is(err, sensorgrant.ErrNarrowForbidden) {
		t.Fatalf("no grant permission: %v", err)
	}
	// ... but can narrow.
	narrow := input(g)
	narrow.Tools = []string{"subfinder"}
	g2, err := f.svc.Update(ctx, narrowOnly(tid, uid), sid, narrow)
	if err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if g2.Version != 2 || g2.Profile != sensordom.ProfileCustom {
		t.Fatalf("after narrow: %+v", g2)
	}
	// A stale version loses (compare-and-swap).
	if _, err := f.svc.Update(ctx, admin(tid, uid), sid, promote); !errors.Is(err, sensorgrant.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	// The widen permission promotes.
	promote = input(g2)
	promote.TrustLevel = sensordom.TrustTrusted
	g3, err := f.svc.Update(ctx, admin(tid, uid), sid, promote)
	if err != nil || g3.TrustLevel != sensordom.TrustTrusted || g3.Version != 3 {
		t.Fatalf("promote: %+v %v", g3, err)
	}
	stored, _ := f.grants.Get(ctx, tid, sid)
	if stored.Version != 3 || stored.UpdatedBy == nil || *stored.UpdatedBy != uid || stored.Tools[0] != "subfinder" {
		t.Fatalf("stored: %+v", stored)
	}

	// legacy-broad cannot be chosen; a profile rebuild keeps the trust level.
	if _, err := f.svc.Update(ctx, admin(tid, uid), sid, sensorgrant.UpdateInput{Profile: sensordom.ProfileLegacyBroad}); !errors.Is(err, sensorgrant.ErrLegacyProfile) {
		t.Fatalf("legacy profile: %v", err)
	}
	// custom (tools: subfinder) -> easm-external lifts the tool limit: a widening.
	g4, err := f.svc.Update(ctx, admin(tid, uid), sid, sensorgrant.UpdateInput{Profile: sensordom.ProfileEASMExternal})
	if err != nil || g4.Profile != sensordom.ProfileEASMExternal || g4.TrustLevel != sensordom.TrustTrusted || g4.TargetNetwork != sensordom.TargetNetworkPublic {
		t.Fatalf("profile rebuild: %+v %v", g4, err)
	}

	// A zone of another organization cannot be named.
	foreignZone := shared.NewID()
	f.exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, 'foreign', ARRAY['10.0.0.0/8']::cidr[])`, foreignZone.String(), otherTenant.String())
	z := input(g4)
	z.ZoneIDs = []shared.ID{foreignZone}
	if _, err := f.svc.Update(ctx, admin(tid, uid), sid, z); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("foreign zone: %v", err)
	}
}

func TestGrant_LegacyBackfillShape_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, _ := f.org()
	sid := f.sensor(tid, nil, nil)
	// Simulate a sensor that existed before the migration: the backfill
	// statement's values.
	f.exec(`UPDATE sensors SET trust_level = 'trusted' WHERE id = $1`, sid.String())
	f.exec(`UPDATE sensor_grants SET profile = 'legacy-broad', job_types = NULL, tier_ceiling = 2,
		allow_credentials = TRUE, allow_push_ingest = TRUE, remote_actions = ARRAY['diagnostics','rotate_key','update']
		WHERE sensor_id = $1`, sid.String())
	g, err := f.grants.Get(ctx, tid, sid)
	if err != nil {
		t.Fatal(err)
	}
	want := sensordom.LegacyBroadGrant(tid, sid)
	if !g.LegacyBroad() || len(sensordom.Changed(*want, *g)) != 0 {
		t.Fatalf("legacy grant differs from the domain's: %v", sensordom.Changed(*want, *g))
	}
}

type refusals struct {
	mu   sync.Mutex
	dims []string
	push int
}

func (r *refusals) ObserveGrantRefusal(_ context.Context, _, _ shared.ID, _ string, g *sensordom.GrantRefusal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dims = append(r.dims, g.Dimension)
}

func (r *refusals) ObservePushRefusal(context.Context, shared.ID, shared.ID, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.push++
}

func (f *fixture) command(tenantID shared.ID, cmdType commanddom.CommandType, p map[string]any, zone *shared.ID) *commanddom.Command {
	f.t.Helper()
	b, _ := json.Marshal(p)
	c, err := commanddom.NewCommand(tenantID, cmdType, commanddom.CommandPriorityNormal, b)
	if err != nil {
		f.t.Fatal(err)
	}
	c.ScanZoneID = zone
	if err := postgres.NewCommandRepository(f.pg).Create(context.Background(), c); err != nil {
		f.t.Fatalf("create command: %v", err)
	}
	return c
}

func polled(t *testing.T, svc *command.Service, tid, sid shared.ID, caps []string) map[shared.ID]bool {
	t.Helper()
	cmds, err := svc.Poll(context.Background(), command.PollInput{TenantID: tid.String(), SensorID: sid.String(), Capabilities: caps, Limit: 50})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	out := map[shared.ID]bool{}
	for _, c := range cmds {
		out[c.ID] = true
	}
	return out
}

// Threats 2, 11, 14, 15: poll withholds and claim by id refuses what the
// grant does not cover; a refused claim is reported with its dimension.
func TestGrant_EnforcedOnPollAndClaim_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, uid := f.org()
	sid := f.sensor(tid, []string{"nuclei", "subfinder"}, []string{"recon", "vulnerability"})
	obs := &refusals{}
	cmds := command.NewService(postgres.NewCommandRepository(f.pg), logger.NewNop(),
		command.WithSensorLookup(postgres.NewSensorRepository(f.pg)), command.WithGrants(f.grants, obs))
	caps := []string{"recon", "vulnerability"}

	passive := f.command(tid, commanddom.CommandTypeScan, map[string]any{"scanner": "subfinder", "targets": []string{"example.com"}}, nil)
	active := f.command(tid, commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "targets": []string{"example.com"}}, nil)
	cred := f.command(tid, commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "targets": []string{"example.com"},
		"scanner_config": map[string]any{"api_key": "sk-live-abcdefghijklmnop"}}, nil)
	private := f.command(tid, commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "targets": []string{"10.9.8.7"}}, nil)

	// New: passive work only (threat 2).
	got := polled(t, cmds, tid, sid, caps)
	if !got[passive.ID] || got[active.ID] || got[cred.ID] {
		t.Fatalf("New sensor poll: %v", got)
	}
	if _, err := cmds.Acknowledge(ctx, tid.String(), sid.String(), active.ID.String()); !errors.Is(err, command.ErrOutOfGrant) {
		t.Fatalf("New sensor claimed a T1 job: %v", err)
	}
	if len(obs.dims) != 1 || obs.dims[0] != sensordom.DimTier {
		t.Fatalf("refusal not reported: %v", obs.dims)
	}

	// Trusted internal-network-scanner: T1 yes, credentials no (threat 14).
	g, _ := f.svc.Get(ctx, tid, sid)
	in := input(g)
	in.TrustLevel = sensordom.TrustTrusted
	if g, _ = f.svc.Update(ctx, admin(tid, uid), sid, in); g == nil {
		t.Fatal("promote failed")
	}
	got = polled(t, cmds, tid, sid, caps)
	if !got[active.ID] || got[cred.ID] || !got[private.ID] {
		t.Fatalf("trusted poll: %v", got)
	}
	if _, err := cmds.Acknowledge(ctx, tid.String(), sid.String(), cred.ID.String()); !errors.Is(err, command.ErrOutOfGrant) {
		t.Fatalf("credential job claimed without allow_credentials: %v", err)
	}
	if obs.dims[len(obs.dims)-1] != sensordom.DimCredentials {
		t.Fatalf("credential refusal dimension: %v", obs.dims)
	}

	// easm-external: no private targets (threat 15). Narrowing applies on
	// the next request.
	if _, err := f.svc.Update(ctx, narrowOnly(tid, uid), sid, sensorgrant.UpdateInput{Profile: sensordom.ProfileEASMExternal}); err != nil {
		t.Fatal(err)
	}
	got = polled(t, cmds, tid, sid, caps)
	if got[private.ID] || !got[active.ID] {
		t.Fatalf("easm-external poll: %v", got)
	}
	if _, err := cmds.Acknowledge(ctx, tid.String(), sid.String(), private.ID.String()); !errors.Is(err, command.ErrOutOfGrant) {
		t.Fatalf("private target claimed by easm-external: %v", err)
	}
	if _, err := cmds.Acknowledge(ctx, tid.String(), sid.String(), active.ID.String()); err != nil {
		t.Fatalf("in-grant claim: %v", err)
	}

	// Threat 11, zones: a grant pinned to zone A never gets zone B's work.
	zA, zB := shared.NewID(), shared.NewID()
	for _, z := range []shared.ID{zA, zB} {
		f.exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, $3, ARRAY['10.0.0.0/8']::cidr[])`, z.String(), tid.String(), "z-"+z.String())
		f.exec(`INSERT INTO scan_zone_sensors (tenant_id, zone_id, sensor_id) VALUES ($1, $2, $3)`, tid.String(), z.String(), sid.String())
	}
	g, _ = f.svc.Get(ctx, tid, sid)
	in = input(g)
	in.ZoneIDs = []shared.ID{zA}
	if _, err := f.svc.Update(ctx, narrowOnly(tid, uid), sid, in); err != nil {
		t.Fatal(err)
	}
	inB := f.command(tid, commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "targets": []string{"example.org"}}, &zB)
	inA := f.command(tid, commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "targets": []string{"example.org"}}, &zA)
	got = polled(t, cmds, tid, sid, caps)
	if got[inB.ID] || !got[inA.ID] {
		t.Fatalf("zone-pinned poll: %v", got)
	}
	if _, err := cmds.Acknowledge(ctx, tid.String(), sid.String(), inB.ID.String()); !errors.Is(err, command.ErrOutOfGrant) {
		t.Fatalf("other zone claimed: %v", err)
	}
}

// The capability gate now applies to a claim by id too (RFC-052 §3): a
// sensor cannot claim a command whose required capabilities it lacks, even
// without grants.
func TestClaimByID_RequiresCapabilities_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, _ := f.org()
	sid := f.sensor(tid, []string{"nuclei"}, []string{"recon"})
	repo := postgres.NewCommandRepository(f.pg)
	c := f.command(tid, commanddom.CommandTypeValidate, map[string]any{"executor_kind": "nuclei", "required_capabilities": []string{"validate:nuclei"}}, nil)
	ok, err := repo.ClaimForSensor(ctx, tid, c.ID, sid.String())
	if err != nil || ok {
		t.Fatalf("claim without the capability: ok=%v err=%v", ok, err)
	}
	f.exec(`UPDATE sensors SET capabilities = ARRAY['recon','validate:nuclei'], reported_capabilities = ARRAY['recon','validate:nuclei'] WHERE id = $1`, sid.String())
	if ok, err = repo.ClaimForSensor(ctx, tid, c.ID, sid.String()); err != nil || !ok {
		t.Fatalf("claim with the capability: ok=%v err=%v", ok, err)
	}
}

// Threat 13: results without a job need push ingest in the effective grant.
func TestGrant_PushIngest_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, uid := f.org()
	sid := f.sensor(tid, nil, nil)
	obs := &refusals{}
	ing := ingest.NewService(nil, nil, nil, nil, nil, nil, nil, nil, logger.NewNop())
	ing.SetGrants(f.grants, obs)
	agt := &sensordom.Sensor{ID: sid, TenantID: &tid, Type: sensordom.SensorTypeCollector, Status: sensordom.SensorStatusActive}
	report := ingestReport()

	if err := ing.AdmitQueued(ctx, agt, report); !errors.Is(err, ingest.ErrPushIngestNotGranted) {
		t.Fatalf("New sensor pushed without a job: %v", err)
	}
	// A profile with push is still off while New.
	if _, err := f.svc.Update(ctx, admin(tid, uid), sid, sensorgrant.UpdateInput{Profile: "collector:tenable-sc"}); err != nil {
		t.Fatal(err)
	}
	if err := ing.AdmitQueued(ctx, agt, report); !errors.Is(err, ingest.ErrPushIngestNotGranted) {
		t.Fatalf("New collector pushed without a job: %v", err)
	}
	g, _ := f.svc.Get(ctx, tid, sid)
	in := input(g)
	in.TrustLevel = sensordom.TrustTrusted
	if _, err := f.svc.Update(ctx, admin(tid, uid), sid, in); err != nil {
		t.Fatal(err)
	}
	if err := ing.AdmitQueued(ctx, agt, report); err != nil {
		t.Fatalf("trusted collector with push refused: %v", err)
	}
	if obs.push != 2 {
		t.Fatalf("push refusals reported: %d", obs.push)
	}
	// Another tenant's sensor id reads as no grant: refused.
	other, _ := f.org()
	foreign := &sensordom.Sensor{ID: sid, TenantID: &other, Type: sensordom.SensorTypeCollector, Status: sensordom.SensorStatusActive}
	if err := ing.AdmitQueued(ctx, foreign, report); !errors.Is(err, ingest.ErrPushIngestNotGranted) {
		t.Fatalf("cross-tenant push: %v", err)
	}
}

// Gated heartbeat actions ring only when the grant lists them.
func TestGrant_DoorbellActions_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, _ := f.org()
	sid := f.sensor(tid, nil, nil)
	cfg := sensorapp.DefaultDoorbellConfig()
	cfg.KeyRenewBefore = time.Hour
	bell := sensorapp.NewDoorbell(nil, cfg.Normalized(5*time.Minute), logger.NewNop())
	bell.SetGrants(f.grants)
	exp := time.Now().Add(time.Minute)
	req := sensorapp.DoorbellRequest{Identity: sensorapp.SensorIdentity{Sensor: &sensordom.Sensor{ID: sid, TenantID: &tid}, KeyExpiresAt: &exp}}
	if h := bell.Ring(ctx, req); len(h.Actions) != 0 {
		t.Fatalf("rotate_key rang for a grant without it: %v", h.Actions)
	}
	f.exec(`UPDATE sensor_grants SET remote_actions = ARRAY['rotate_key'] WHERE sensor_id = $1`, sid.String())
	if h := bell.Ring(ctx, req); len(h.Actions) != 1 || h.Actions[0] != sensordom.ActionRotateKey {
		t.Fatalf("rotate_key with the grant: %v", h.Actions)
	}
}

func ingestReport() *ctis.Report {
	return &ctis.Report{Version: "1.0", Metadata: ctis.ReportMetadata{ID: "grant-push"}}
}

// A sensor on the default grant the insert trigger gives it retests the
// finding of a T1 tool once it is trusted, and refuses it while New (the
// trust level caps it at T0). Before, no default profile listed retest, so
// "Retest now" waited out its deadline with no result.
func TestGrant_DefaultSensorRetests_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, uid := f.org()
	caps := []string{"vulnerability", "retest:nuclei"}
	sid := f.sensor(tid, []string{"nuclei"}, caps)
	obs := &refusals{}
	cmds := command.NewService(postgres.NewCommandRepository(f.pg), logger.NewNop(),
		command.WithSensorLookup(postgres.NewSensorRepository(f.pg)), command.WithGrants(f.grants, obs))

	g, err := f.svc.Get(ctx, tid, sid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !slices.Contains(g.JobTypes, "retest") {
		t.Fatalf("default grant job types %v: no retest", g.JobTypes)
	}
	retest := func() *commanddom.Command {
		return f.command(tid, commanddom.CommandTypeRetest, map[string]any{
			"scanner": "nuclei", "retest_id": shared.NewID().String(), "timeout_seconds": 120,
			"targets": []string{"https://app.example.com"},
			"items": []map[string]any{{"ref": shared.NewID().String(), "target": "https://app.example.com",
				"kind": "finding", "rule_id": "CVE-2021-41773"}},
			"required_capabilities": []string{"retest:nuclei"},
		}, nil)
	}

	// New: refused (tier), on poll and on claim by id.
	first := retest()
	if polled(t, cmds, tid, sid, caps)[first.ID] {
		t.Fatal("New sensor was offered a T1 retest")
	}
	if _, err := cmds.Acknowledge(ctx, tid.String(), sid.String(), first.ID.String()); !errors.Is(err, command.ErrOutOfGrant) {
		t.Fatalf("New sensor claimed a T1 retest: %v", err)
	}
	if len(obs.dims) == 0 || obs.dims[len(obs.dims)-1] != sensordom.DimTier {
		t.Fatalf("refusal dimension: %v", obs.dims)
	}

	// Trusted: offered and claimed.
	in := input(g)
	in.TrustLevel = sensordom.TrustTrusted
	if g, err = f.svc.Update(ctx, admin(tid, uid), sid, in); err != nil || g == nil {
		t.Fatalf("promote: %v", err)
	}
	if !polled(t, cmds, tid, sid, caps)[first.ID] {
		t.Fatal("trusted default sensor was not offered the retest")
	}
	if _, err := cmds.Acknowledge(ctx, tid.String(), sid.String(), first.ID.String()); err != nil {
		t.Fatalf("trusted default sensor could not claim the retest: %v", err)
	}
}

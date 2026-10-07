package retest_test

// Continuous retest (RFC-039) end to end against a migrated Postgres: request →
// two real validate commands → the sensor's results → the finding moves (or,
// for an unreachable target, does not). DB-gated: needs DATABASE_URL naming a
// disposable test database (testdb.URL), never the live one.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"

	_ "github.com/lib/pq"

	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type sensorsOnline bool

func (s sensorsOnline) HasNucleiValidationSensor(context.Context, shared.ID) (bool, error) {
	return bool(s), nil
}

// HasRetestSensor: no tool retest handler online (the validate path).
func (s sensorsOnline) HasRetestSensor(context.Context, shared.ID, string) (bool, error) {
	return false, nil
}

type fixture struct {
	t      *testing.T
	db     *sql.DB
	pg     *postgres.DB
	repo   *postgres.FindingRetestRepository
	tenant shared.ID
	user   shared.ID
	asset  shared.ID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping retest DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	fx := &fixture{t: t, db: db, pg: &postgres.DB{DB: db}, tenant: shared.NewID(), user: shared.NewID()}
	fx.repo = postgres.NewFindingRetestRepository(fx.pg)
	fx.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'retest IT', $2)`, fx.tenant.String(), "retest-"+fx.tenant.String())
	fx.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'analyst')`, fx.user.String(), fx.user.String()+"@retest.test")
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM commands WHERE tenant_id = $1`, fx.tenant.String())
		_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, fx.tenant.String())
		_, _ = db.ExecContext(bg, `DELETE FROM users WHERE id = $1`, fx.user.String())
	})
	// The tenant authorizes its own domain for active checks (RFC-036 §6.3):
	// an asset with no attribution record is probed only inside a scope
	// target or under a seed.
	fx.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.example.com', 'active')`, fx.tenant.String())
	fx.asset = fx.newAsset("shop.example.com")
	return fx
}

func (fx *fixture) exec(q string, args ...any) {
	fx.t.Helper()
	if _, err := fx.db.ExecContext(context.Background(), q, args...); err != nil {
		fx.t.Fatalf("exec %q: %v", q, err)
	}
}

func (fx *fixture) newAsset(name string) shared.ID {
	id := shared.NewID()
	fx.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'domain', 'active')`,
		id.String(), fx.tenant.String(), name)
	return id
}

// newFinding inserts a nuclei finding in the given status.
func (fx *fixture) newFinding(asset shared.ID, status, template string) shared.ID {
	id := shared.NewID()
	fx.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, file_path, message, severity,
			fingerprint, status, resolved_at, resolved_by, resolution)
		VALUES ($1::uuid, $2, $3, 'dast', 'nuclei', $4, 'https://shop.example.com/admin', 'nuclei hit', 'high', $1::text, $5::text,
			CASE WHEN $5::text = 'resolved' THEN NOW() END, CASE WHEN $5::text = 'resolved' THEN $6::uuid END,
			CASE WHEN $5::text = 'resolved' THEN 'patched' END)`,
		id.String(), fx.tenant.String(), asset.String(), template, status, fx.user.String())
	return id
}

func (fx *fixture) service() *retestapp.Service {
	return fx.serviceWith(sensorsOnline(true))
}

// serviceWith is the service with the given sensor availability.
func (fx *fixture) serviceWith(sensors retestapp.SensorAvailability) *retestapp.Service {
	svc := retestapp.NewService(fx.repo, postgres.NewFindingRepository(fx.pg), postgres.NewAssetRepository(fx.pg),
		postgres.NewCommandRepository(fx.pg), validation.NewCommandDispatcher(postgres.NewCommandRepository(fx.pg), fx.gate(), logger.NewNop()),
		sensors, logger.NewNop())
	// The production policy (settings.retest.auto_resolve) and evidence store.
	svc.SetPolicy(retestapp.TenantPolicy{Tenants: postgres.NewTenantRepository(fx.pg)})
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		fx.t.Fatal(err)
	}
	svc.SetEvidenceStore(evidenceapp.NewService(postgres.NewFindingEvidenceRepository(fx.pg), cipher, nil, nil, nil, logger.NewNop()))
	return svc
}

// gate is the production active-probe gate over the test database.
func (fx *fixture) gate() *scanapp.Service {
	log := logger.NewNop()
	scope := scopeapp.NewService(postgres.NewScopeTargetRepository(fx.pg), postgres.NewScopeExclusionRepository(fx.pg),
		postgres.NewAssetRepository(fx.pg), log)
	return scanapp.NewTargetGate(scope, easmapp.NewActiveGate(postgres.NewAttributionRepository(fx.pg), postgres.NewAssetRepository(fx.pg), scope, postgres.NewEASMSeedRepository(fx.pg)), postgres.NewScanZoneRepository(fx.pg), nil, log)
}

// finish reports a sensor result for a command: completed with an outcome, or
// failed when outcome is "".
func (fx *fixture) finish(cmd *shared.ID, outcome, summary string) {
	fx.t.Helper()
	if cmd == nil {
		fx.t.Fatal("retest has no command")
	}
	if outcome == "" {
		fx.exec(`UPDATE commands SET status = 'failed', error_message = 'sensor crashed', completed_at = NOW() WHERE id = $1`, cmd.String())
		return
	}
	res, _ := json.Marshal(map[string]any{"metadata": map[string]any{"outcome": outcome, "summary": summary}})
	fx.exec(`UPDATE commands SET status = 'completed', result = $2, completed_at = NOW() WHERE id = $1`, cmd.String(), res)
}

// attemptItems is the proof a re-run reports: one HTTP exchange to url that
// answered status (0: no response).
func attemptItems(url string, status int) []map[string]any {
	ex := map[string]any{"request": map[string]any{"method": "GET", "url": url,
		"headers": []map[string]string{{"name": "Cookie", "value": "sid=retest-session-value"}}}}
	if status > 0 {
		ex["response"] = map[string]any{"status": status, "body": "not found"}
	}
	return []map[string]any{{"kind": "http_exchange", "http": ex}}
}

// finishAttempt completes a template re-run that reports its attempt.
func (fx *fixture) finishAttempt(cmd *shared.ID, outcome, url string, status int) {
	fx.t.Helper()
	res, _ := json.Marshal(map[string]any{"metadata": map[string]any{"outcome": outcome, "summary": "re-run",
		"evidence": map[string]any{"evidence_items": attemptItems(url, status)}}})
	fx.exec(`UPDATE commands SET status = 'completed', result = $2, completed_at = NOW() WHERE id = $1`, cmd.String(), res)
}

func (fx *fixture) autoResolve(on bool) {
	fx.exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{retest}',
		COALESCE(settings->'retest', '{}'::jsonb) || jsonb_build_object('auto_resolve', $2::boolean)) WHERE id = $1`,
		fx.tenant.String(), on)
}

func (fx *fixture) findingState(id shared.ID) (status, method, resolvedBy string) {
	fx.t.Helper()
	var m, by sql.NullString
	if err := fx.db.QueryRow(`SELECT status, resolution_method, resolved_by::text FROM findings WHERE id = $1`, id.String()).
		Scan(&status, &m, &by); err != nil {
		fx.t.Fatal(err)
	}
	return status, m.String, by.String
}

func (fx *fixture) retest(id shared.ID) *retestdom.Retest {
	fx.t.Helper()
	rt, err := fx.repo.GetByID(context.Background(), fx.tenant, id)
	if err != nil {
		fx.t.Fatal(err)
	}
	return rt
}

func (fx *fixture) request(svc *retestapp.Service, finding shared.ID) *retestdom.Retest {
	fx.t.Helper()
	user := fx.user
	rt, err := svc.Request(context.Background(), retestapp.RequestInput{
		TenantID: fx.tenant, FindingID: finding, Trigger: retestdom.TriggerManual, RequestedBy: &user,
	})
	if err != nil {
		fx.t.Fatalf("request retest: %v", err)
	}
	return rt
}

// The commands a retest queues are real validate commands: the template re-run
// routed to validate:nuclei, the probe to validate, both tagged with the retest.
func TestRetestDB_QueuesTwoScopedValidateCommands(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	f := fx.newFinding(fx.asset, "confirmed", "CVE-2024-1234")
	rt := fx.request(svc, f)

	rows, err := fx.db.Query(`SELECT type, payload FROM commands WHERE tenant_id = $1 ORDER BY created_at`, fx.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	kinds := map[string]validation.ValidateCommandPayload{}
	for rows.Next() {
		var typ string
		var raw []byte
		if err := rows.Scan(&typ, &raw); err != nil {
			t.Fatal(err)
		}
		var p validation.ValidateCommandPayload
		_ = json.Unmarshal(raw, &p)
		if typ != "validate" || p.RetestID != rt.ID.String() || p.FindingID != f.String() {
			t.Errorf("unexpected command %s %+v", typ, p)
		}
		kinds[p.ExecutorKind] = p
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	nuc, ok := kinds["nuclei"]
	if !ok || nuc.TemplateID != "CVE-2024-1234" || nuc.Target.Address != "https://shop.example.com" ||
		len(nuc.RequiredCapabilities) != 1 || nuc.RequiredCapabilities[0] != "validate:nuclei" {
		t.Errorf("template re-run command wrong: %+v", nuc)
	}
	if sc, ok := kinds["safe-check"]; !ok || sc.Target.Address != nuc.Target.Address || sc.TemplateID != "" {
		t.Errorf("reachability probe command wrong: %+v", sc)
	}
}

// RFC-057 R2: a bare "not detected" on a host that answers a TCP probe is
// not reproduced (the finding stays); only an attempt at the finding's own
// endpoint that got an answer is a confirmed fix, which awaits a person
// (validated_fixed) unless the tenant auto-resolves.
func TestRetestDB_NoMatchWithoutEndpointProofIsNotReproduced(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	f := fx.newFinding(fx.asset, "confirmed", "exposed-admin-panel")
	rt := fx.request(svc, f)

	fx.finish(rt.CheckCommandID, "not_detected", "detection template did not match")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)
	if got := fx.retest(rt.ID); got.Status != retestdom.StatusPending {
		t.Fatalf("settled with one check outstanding: %+v", got)
	}
	fx.finish(rt.ReachCommandID, "detected", "target is still reachable")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)

	got := fx.retest(rt.ID)
	if got.Outcome != retestdom.OutcomeNotReproduced || got.ReasonCode != retestdom.ReasonNoEndpointProof || got.ResultStatus != "confirmed" {
		t.Fatalf("retest = %+v, want not_reproduced, finding unchanged", got)
	}
	if status, _, _ := fx.findingState(f); status != "confirmed" {
		t.Errorf("finding moved to %s", status)
	}
	var actorType, actorName string
	if err := fx.db.QueryRow(`SELECT actor_type, actor_name FROM finding_activities
		WHERE finding_id = $1 AND activity_type = 'retest_completed'`, f.String()).Scan(&actorType, &actorName); err != nil {
		t.Fatalf("retest_completed activity: %v", err)
	}
	if actorType != "system" || actorName != "system: retest" {
		t.Errorf("activity actor = %s/%s, want system/system: retest", actorType, actorName)
	}
}

func TestRetestDB_ConfirmedFixAwaitsAPersonUnlessAutoResolve(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	settle := func(f shared.ID, url string, status int) *retestdom.Retest {
		t.Helper()
		rt := fx.request(svc, f)
		fx.finishAttempt(rt.CheckCommandID, "not_detected", url, status)
		fx.finish(rt.ReachCommandID, "detected", "target answered")
		svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)
		return fx.retest(rt.ID)
	}

	f := fx.newFinding(fx.asset, "confirmed", "exposed-admin-panel")
	// The sensor that claims the check is recorded on the retest (a run:
	// finding + command + sensor).
	sensor := shared.NewID()
	fx.exec(`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status) VALUES ($1, $2, 'retest-runner', $3, 'octs_rt', 'active')`,
		sensor.String(), fx.tenant.String(), "hash-"+sensor.String())
	settleClaimed := func(f shared.ID, url string, status int) *retestdom.Retest {
		t.Helper()
		rt := fx.request(svc, f)
		fx.exec(`UPDATE commands SET sensor_id = $2 WHERE id = $1`, rt.CheckCommandID.String(), sensor.String())
		fx.finishAttempt(rt.CheckCommandID, "not_detected", url, status)
		fx.finish(rt.ReachCommandID, "detected", "target answered")
		svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)
		return fx.retest(rt.ID)
	}
	got := settleClaimed(f, "https://shop.example.com/admin", 404)
	if got.SensorID == nil || *got.SensorID != sensor || got.CheckCommandID == nil {
		t.Fatalf("retest run linkage = sensor %v command %v, want the claiming sensor and the check command", got.SensorID, got.CheckCommandID)
	}
	if got.Outcome != retestdom.OutcomeConfirmedFixed || got.ResultStatus != "validated_fixed" ||
		!strings.Contains(got.Reason, "https://shop.example.com/admin answered 404") {
		t.Fatalf("retest = %+v, want confirmed_fixed → validated_fixed", got)
	}
	if status, _, _ := fx.findingState(f); status != "validated_fixed" {
		t.Errorf("finding = %s, want validated_fixed", status)
	}
	// The attempt's proof is kept, masked, on the finding.
	var n int
	if err := fx.db.QueryRow(`SELECT count(*) FROM finding_evidence WHERE tenant_id = $1 AND finding_id = $2 AND retest_id = $3
		AND origin = 'retest' AND content::text NOT LIKE '%retest-session-value%'`, fx.tenant.String(), f.String(), got.ID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("retest evidence rows = %d, want 1 (masked)", n)
	}

	// The re-run requested another path (the 2026-10-07 false fix): no conclusion.
	g := fx.newFinding(fx.newAsset("api.example.com"), "confirmed", "exposed-admin-panel-2")
	fx.exec(`UPDATE findings SET file_path = 'https://api.example.com/wp-admin/js/theme.js' WHERE id = $1`, g.String())
	got = settle(g, "https://api.example.com/wp-admin/js/theme.js/wp-admin/js/theme.js", 404)
	if got.Outcome != retestdom.OutcomeInconclusive || got.ReasonCode != retestdom.ReasonEndpointMismatch {
		t.Fatalf("path-doubled attempt = %+v, want inconclusive endpoint_mismatch", got)
	}

	// A blocked attempt is not a fix.
	b := fx.newFinding(fx.newAsset("waf.example.com"), "confirmed", "exposed-admin-panel-3")
	fx.exec(`UPDATE findings SET file_path = 'https://waf.example.com/admin' WHERE id = $1`, b.String())
	if got = settle(b, "https://waf.example.com/admin", 403); got.ReasonCode != retestdom.ReasonBlocked {
		t.Fatalf("403 attempt = %+v, want blocked", got)
	}

	// With auto_resolve the confirmed fix resolves, by the requester.
	fx.autoResolve(true)
	h := fx.newFinding(fx.newAsset("auto.example.com"), "confirmed", "exposed-admin-panel-4")
	fx.exec(`UPDATE findings SET file_path = 'https://auto.example.com/admin' WHERE id = $1`, h.String())
	if got = settle(h, "https://auto.example.com/admin", 200); got.ResultStatus != "resolved" {
		t.Fatalf("auto-resolve retest = %+v", got)
	}
	if status, method, by := fx.findingState(h); status != "resolved" || method != "retest_verified" || by != fx.user.String() {
		t.Errorf("finding = %s/%s/%s, want resolved/retest_verified/<requester>", status, method, by)
	}
}

// An unreachable target is unknown, never fixed: nuclei prints nothing for a
// host that does not answer, which the sensor reports as not_detected.
func TestRetestDB_UnreachableTargetIsUnknownNotFixed(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()

	refused := fx.newFinding(fx.asset, "confirmed", "tpl-refused")
	rt := fx.request(svc, refused)
	fx.finish(rt.CheckCommandID, "not_detected", "")
	fx.finish(rt.ReachCommandID, "not_detected", "target is no longer reachable (connection refused)")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)
	got := fx.retest(rt.ID)
	if got.Outcome != retestdom.OutcomeInconclusive || !strings.HasPrefix(got.Reason, "target unreachable") {
		t.Fatalf("retest = %+v, want unknown / target unreachable", got)
	}
	if status, _, _ := fx.findingState(refused); status != "confirmed" {
		t.Errorf("unreachable target moved the finding to %s", status)
	}

	// The probe itself failing (sensor error) is unknown too.
	failed := fx.newFinding(fx.newAsset("api.example.com"), "fix_applied", "tpl-failed")
	rt2 := fx.request(svc, failed)
	fx.finish(rt2.CheckCommandID, "not_detected", "")
	fx.finish(rt2.ReachCommandID, "", "")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt2.ReachCommandID)
	if got := fx.retest(rt2.ID); got.Outcome != retestdom.OutcomeInconclusive {
		t.Fatalf("retest with a failed probe = %+v, want unknown", got)
	}
	if status, _, _ := fx.findingState(failed); status != "fix_applied" {
		t.Errorf("failed probe moved the finding to %s", status)
	}
}

// A retest that sees a resolved finding again reopens it as a regression, with
// the system: retest actor.
func TestRetestDB_StillPresentReopensResolvedFinding(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	f := fx.newFinding(fx.asset, "resolved", "tpl-regress")
	rt := fx.request(svc, f)
	fx.finish(rt.CheckCommandID, "detected", "exposure still reproducible")
	fx.finish(rt.ReachCommandID, "detected", "")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)

	if got := fx.retest(rt.ID); got.Outcome != retestdom.OutcomeStillVulnerable || got.ResultStatus != "confirmed" {
		t.Fatalf("retest = %+v, want still_present → confirmed", got)
	}
	status, _, by := fx.findingState(f)
	if status != "confirmed" || by != "" {
		t.Errorf("finding = %s (resolved_by %q), want confirmed and the resolution cleared", status, by)
	}
	var isRegression bool
	var changes []byte
	if err := fx.db.QueryRow(`SELECT COALESCE(is_regression, false) FROM findings WHERE id = $1`, f.String()).Scan(&isRegression); err != nil {
		t.Fatal(err)
	}
	if !isRegression {
		t.Error("retest reopen not counted as a regression")
	}
	if err := fx.db.QueryRow(`SELECT changes FROM finding_activities WHERE finding_id = $1 AND activity_type = 'retest_completed'`,
		f.String()).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(changes, &c)
	if c["regression"] != true || c["old_status"] != "resolved" || c["new_status"] != "confirmed" || c["actor"] != "system: retest" {
		t.Errorf("activity changes = %v", c)
	}
}

func TestRetestDB_OneInFlightPerFindingThenCooldown(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	f := fx.newFinding(fx.asset, "confirmed", "tpl-once")
	rt := fx.request(svc, f)
	user := fx.user
	_, err := svc.Request(context.Background(), retestapp.RequestInput{TenantID: fx.tenant, FindingID: f, Trigger: retestdom.TriggerManual, RequestedBy: &user})
	if !errors.Is(err, retestdom.ErrRateLimited) && !errors.Is(err, retestdom.ErrInFlight) {
		t.Fatalf("second request while one is pending: err = %v, want in-flight or rate-limited", err)
	}
	fx.finish(rt.CheckCommandID, "detected", "")
	fx.finish(rt.ReachCommandID, "detected", "")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)
	_, err = svc.Request(context.Background(), retestapp.RequestInput{TenantID: fx.tenant, FindingID: f, Trigger: retestdom.TriggerManual, RequestedBy: &user})
	if !errors.Is(err, retestdom.ErrRateLimited) {
		t.Fatalf("request inside the cooldown: err = %v, want rate-limited", err)
	}
}

// A retest whose sensor never answers is settled unknown by the sweep once its
// deadline passes; the finding is not touched.
func TestRetestDB_SweepSettlesPastDeadlineAsUnknown(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	f := fx.newFinding(fx.asset, "in_progress", "tpl-silent")
	rt := fx.request(svc, f)

	svc.SetClock(func() time.Time { return time.Now().Add(retestapp.Deadline + time.Minute) })
	if _, err := svc.Sweep(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	got := fx.retest(rt.ID)
	if got.Outcome != retestdom.OutcomeInconclusive || got.Reason != "no sensor result before the deadline" {
		t.Fatalf("retest = %+v, want unknown / no result before the deadline", got)
	}
	if status, _, _ := fx.findingState(f); status != "in_progress" {
		t.Errorf("silent sensor moved the finding to %s", status)
	}
}

// Ineligible findings are refused before anything is queued.
func TestRetestDB_IneligibleFindingsAreRefused(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	user := fx.user
	fp := fx.newFinding(fx.asset, "false_positive", "tpl-fp")
	notNuclei := fx.newFinding(fx.asset, "confirmed", "tpl-x")
	fx.exec(`UPDATE findings SET tool_name = 'trivy' WHERE id = $1`, notNuclei.String())
	destructive := fx.newFinding(fx.asset, "confirmed", "apache-dos-check")
	for name, f := range map[string]shared.ID{"false positive": fp, "destructive template": destructive} {
		_, err := svc.Request(context.Background(), retestapp.RequestInput{TenantID: fx.tenant, FindingID: f, Trigger: retestdom.TriggerManual, RequestedBy: &user})
		if !errors.Is(err, retestdom.ErrNotEligible) {
			t.Errorf("%s: err = %v, want not eligible", name, err)
		}
	}
	// A finding of another tool is retested only by that tool's retest
	// handler: with none online the request is refused.
	if _, err := svc.Request(context.Background(), retestapp.RequestInput{TenantID: fx.tenant, FindingID: notNuclei, Trigger: retestdom.TriggerManual, RequestedBy: &user}); !errors.Is(err, retestdom.ErrNoSensor) {
		t.Errorf("not a nuclei finding, no retest sensor: err = %v, want no sensor", err)
	}
	var n int
	_ = fx.db.QueryRow(`SELECT COUNT(*) FROM commands WHERE tenant_id = $1`, fx.tenant.String()).Scan(&n)
	if n != 0 {
		t.Errorf("%d commands queued for ineligible findings", n)
	}
}

// --- no double-fire ---

// rendezvousAuto makes every replica list the due tenants and then wait until
// all of them have, so their claims race for the same tick.
type rendezvousAuto struct {
	*postgres.FindingRetestRepository
	want    int32
	arrived atomic.Int32
	all     chan struct{}
	once    sync.Once
}

func (r *rendezvousAuto) ListDueAutoTenants(ctx context.Context, now time.Time, limit int) ([]retestdom.AutoTenant, error) {
	list, err := r.FindingRetestRepository.ListDueAutoTenants(ctx, now, limit)
	if r.arrived.Add(1) >= r.want {
		r.once.Do(func() { close(r.all) })
	}
	select {
	case <-r.all:
	case <-time.After(3 * time.Second):
	}
	return list, err
}

// Two API replicas run the scheduler at the same moment. The tenant's tick must
// be served once: with a daily cap of 2 and 4 eligible findings, exactly 2
// retests are queued. Without the claim each replica reads "0 queued today" and
// queues its own 2.
func TestRetestDB_TwoSchedulerReplicasDoNotDoubleFire(t *testing.T) {
	fx := newFixture(t)
	fx.exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{retest}', '{"auto_enabled": true, "daily_cap": 2}') WHERE id = $1`,
		fx.tenant.String())
	other := fx.newAsset("api.example.com")
	for i, a := range []shared.ID{fx.asset, fx.asset, other, other} {
		fx.newFinding(a, "confirmed", "tpl-auto-"+string(rune('a'+i)))
	}

	auto := &rendezvousAuto{FindingRetestRepository: fx.repo, want: 2, all: make(chan struct{})}
	replicas := []*retestapp.Service{fx.service(), fx.service()}
	results := make([]retestapp.TickResult, len(replicas))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, svc := range replicas {
		wg.Add(1)
		go func(i int, svc *retestapp.Service) {
			defer wg.Done()
			<-start
			res, err := svc.RunAutoTick(context.Background(), auto)
			if err != nil {
				t.Errorf("replica %d: %v", i, err)
			}
			results[i] = res
		}(i, svc)
	}
	close(start)
	wg.Wait()

	claimed := results[0].TenantsClaimed + results[1].TenantsClaimed
	if claimed != 1 {
		t.Errorf("tenant tick served by %d replicas, want exactly 1 (%+v)", claimed, results)
	}
	var n, distinct int
	if err := fx.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT finding_id) FROM finding_retests WHERE tenant_id = $1 AND trigger = 'auto'`,
		fx.tenant.String()).Scan(&n, &distinct); err != nil {
		t.Fatal(err)
	}
	if n != 2 || distinct != 2 {
		t.Fatalf("auto retests queued = %d (%d findings), want exactly the daily cap of 2", n, distinct)
	}

	// The next tick is not due yet: running again queues nothing.
	auto2 := &rendezvousAuto{FindingRetestRepository: fx.repo, want: 1, all: make(chan struct{})}
	res, err := replicas[0].RunAutoTick(context.Background(), auto2)
	if err != nil || res.TenantsClaimed != 0 {
		t.Errorf("a tick that is not due was served again: %+v %v", res, err)
	}
}

// Auto-retest is off unless the tenant turned it on.
func TestRetestDB_AutoRetestOffByDefault(t *testing.T) {
	fx := newFixture(t)
	fx.newFinding(fx.asset, "confirmed", "tpl-default-off")
	res, err := fx.service().RunAutoTick(context.Background(), fx.repo)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	_ = fx.db.QueryRow(`SELECT COUNT(*) FROM finding_retests WHERE tenant_id = $1`, fx.tenant.String()).Scan(&n)
	if n != 0 {
		t.Errorf("auto-retest queued %d retests for a tenant that never enabled it (%+v)", n, res)
	}
}

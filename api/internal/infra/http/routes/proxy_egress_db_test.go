package routes

// Proxy pools for scan traffic, sensor side (docs/architecture/sensor-proxies.md),
// over the real v2 routes and a migrated database: the egress member a scan
// job carries for the claiming sensor, the fail-closed gate for a sensor that
// cannot honor a pool, the credentials only the leasing sensor fetches, and
// the health report that quarantines a dead endpoint. Requires DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/command"
	proxypoolapp "github.com/openctemio/openctem/api/internal/app/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

const egressSecret = "s3cret-proxy-pass"

func (h *ctlHarness) reportCaps(s ctlSensor, caps ...string) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensors SET reported_capabilities = $2 WHERE id = $1`,
		s.id, pq.Array(caps)); err != nil {
		h.t.Fatalf("report capabilities: %v", err)
	}
}

func (h *ctlHarness) newPool(tenantID, name, text string, isDefault bool) *proxypool.Pool {
	h.t.Helper()
	p, err := h.egress.CreatePool(context.Background(), proxypoolapp.CreatePoolInput{TenantID: tenantID, Name: name,
		IsDefault: isDefault, EndpointsText: &text}, auditapp.AuditContext{TenantID: tenantID})
	if err != nil {
		h.t.Fatalf("create pool: %v", err)
	}
	return p
}

type egressWire struct {
	Mode      string                  `json:"mode"`
	PoolID    string                  `json:"pool_id"`
	AppliesTo string                  `json:"applies_to"`
	Endpoints []proxypool.JobEndpoint `json:"endpoints"`
}

// pollOne polls as a claim-N sensor and returns the commands it got.
func (h *ctlHarness) pollClaim(s ctlSensor) []protov2.Command {
	h.t.Helper()
	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil,
		protov2.HeaderSensorFeatures, protov2.FeatureCapacity)
	h.want(resp, raw, 200, "")
	return decodeAs[protov2.CommandList](h.t, raw).Commands
}

func egressOf(t *testing.T, payload json.RawMessage) *egressWire {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("payload: %v", err)
	}
	raw, ok := fields["egress"]
	if !ok {
		return nil
	}
	var eg egressWire
	if err := json.Unmarshal(raw, &eg); err != nil {
		t.Fatalf("egress: %v", err)
	}
	return &eg
}

func TestProxyEgress_JobCarriesPoolAndCredentialsOnlyForLeaseHolder(t *testing.T) {
	h := newCtlHarnessWith(t, true)
	sA := h.newSensor(h.tenantID, "egress-a")
	h.reportCaps(sA, "net.confined@1", "egress.upstream@1")
	sOther := h.newSensor(h.tenantID, "egress-other")
	h.reportCaps(sOther, "net.confined@1", "egress.upstream@1")
	pool := h.newPool(h.tenantID, "corp", "socks5://alice:"+egressSecret+"@10.0.0.5:1080#dc1\nhttp://10.0.0.6:3128", true)

	id := h.newCommand(h.tenantID, sA.id)
	got := h.pollClaim(sA)
	if len(got) != 1 || got[0].ID != id {
		t.Fatalf("poll = %+v", got)
	}
	if strings.Contains(string(got[0].Payload), egressSecret) || strings.Contains(string(got[0].Payload), "alice") {
		t.Fatalf("credentials in the job payload: %s", got[0].Payload)
	}
	eg := egressOf(t, got[0].Payload)
	if eg == nil || eg.Mode != "pool" || eg.PoolID != pool.ID.String() || eg.AppliesTo != proxypool.AppliesPublic || len(eg.Endpoints) != 2 {
		t.Fatalf("egress = %+v", eg)
	}
	if !eg.Endpoints[0].Auth || eg.Endpoints[0].Host != "10.0.0.5" || eg.Endpoints[1].Auth {
		t.Fatalf("endpoints = %+v", eg.Endpoints)
	}
	// The claim repeat (what a signing sensor runs) carries it too.
	resp, raw := h.call(sA.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
	h.want(resp, raw, 200, "")
	claimed := decodeAs[protov2.Command](t, raw)
	if eg := egressOf(t, claimed.Payload); eg == nil || eg.PoolID != pool.ID.String() {
		t.Fatalf("claim repeat lost the egress: %s", claimed.Payload)
	}
	epoch := strconv.Itoa(got[0].LeaseEpoch)
	credPath := "/api/v2/sensor/commands/" + id + "/" + protov2.EgressCredentialsAction

	resp, raw = h.call(sA.key, http.MethodPost, credPath, map[string]any{"pool_id": pool.ID.String()}, protov2.HeaderLeaseEpoch, epoch)
	h.want(resp, raw, 200, "")
	creds := decodeAs[protov2.EgressCredentialsResponse](t, raw)
	if len(creds.Credentials) != 1 || creds.Credentials[0].Username != "alice" || creds.Credentials[0].Password != egressSecret ||
		creds.Credentials[0].EndpointID != eg.Endpoints[0].ID {
		t.Fatalf("credentials = %+v", creds)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("credentials answer is cacheable")
	}

	// Every refusal looks the same: wrong epoch, another sensor of the
	// tenant, a pool that is not the sensor's, no epoch.
	for name, call := range map[string]func() (*http.Response, []byte){
		"wrong epoch": func() (*http.Response, []byte) {
			return h.call(sA.key, http.MethodPost, credPath, map[string]any{"pool_id": pool.ID.String()}, protov2.HeaderLeaseEpoch, epoch+"9")
		},
		"no epoch": func() (*http.Response, []byte) {
			return h.call(sA.key, http.MethodPost, credPath, map[string]any{"pool_id": pool.ID.String()})
		},
		"other sensor": func() (*http.Response, []byte) {
			return h.call(sOther.key, http.MethodPost, credPath, map[string]any{"pool_id": pool.ID.String()}, protov2.HeaderLeaseEpoch, epoch)
		},
		"other pool": func() (*http.Response, []byte) {
			return h.call(sA.key, http.MethodPost, credPath, map[string]any{"pool_id": sA.id}, protov2.HeaderLeaseEpoch, epoch)
		},
	} {
		resp, raw := call()
		if resp.StatusCode != http.StatusNotFound || strings.Contains(string(raw), egressSecret) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, raw)
		}
	}

	// Another tenant's sensor cannot reach the command or the pool.
	tenantB := h.newTenant()
	sB := h.newSensor(tenantB, "egress-b")
	resp, raw = h.call(sB.key, http.MethodPost, credPath, map[string]any{"pool_id": pool.ID.String()}, protov2.HeaderLeaseEpoch, epoch)
	if resp.StatusCode != http.StatusNotFound || strings.Contains(string(raw), egressSecret) {
		t.Fatalf("cross-tenant credentials: %d %s", resp.StatusCode, raw)
	}
	// A credential lookup by tenant B's own sensor for tenant A's pool.
	if _, err := h.egress.CredentialsFor(context.Background(), mustID(t, tenantB), mustID(t, sB.id), pool.ID.String()); err == nil {
		t.Fatal("tenant B's sensor got tenant A's pool credentials")
	}
}

func TestProxyEgress_UnsupportedSensorGetsNoScanJobs(t *testing.T) {
	h := newCtlHarnessWith(t, true)
	old := h.newSensor(h.tenantID, "egress-old")
	h.reportCaps(old, "net.confined@1") // no egress.upstream@1
	h.newPool(h.tenantID, "corp", "http://10.0.0.6:3128", true)
	id := h.newCommand(h.tenantID, old.id)

	if got := h.pollClaim(old); len(got) != 0 {
		t.Fatalf("an unsupported sensor got %d job(s)", len(got))
	}
	resp, raw := h.call(old.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("claim by id = %d %s, want 409", resp.StatusCode, raw)
	}
	var status string
	if err := h.db.QueryRow(`SELECT status FROM commands WHERE id = $1`, id).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("command %s after a refused claim (%v)", status, err)
	}

	// Direct for that sensor: it scans again, without an egress member, and
	// one a command's creator put in the payload is removed.
	if err := h.egress.AssignSensor(context.Background(), h.tenantID, old.id, proxypool.ModeDirect, "", auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`UPDATE commands SET payload = payload || '{"egress":{"mode":"pool","pool_id":"x","endpoints":[{"host":"203.0.113.9"}]}}'::jsonb WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	got := h.pollClaim(old)
	if len(got) != 1 || egressOf(t, got[0].Payload) != nil {
		t.Fatalf("direct sensor: %+v", got)
	}
}

func TestProxyEgress_SensorPoolAppliesToAllAndReportQuarantines(t *testing.T) {
	h := newCtlHarnessWith(t, true)
	s := h.newSensor(h.tenantID, "egress-seg")
	h.reportCaps(s, "net.confined@1", "egress.upstream@1")
	h.newPool(h.tenantID, "default", "http://10.0.0.6:3128", true)
	seg := h.newPool(h.tenantID, "segment", "socks5://10.9.0.1:1080\nsocks5://10.9.0.2:1080", false)
	if err := h.egress.AssignSensor(context.Background(), h.tenantID, s.id, proxypool.ModePool, seg.ID.String(), auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	id := h.newCommand(h.tenantID, s.id)
	got := h.pollClaim(s)
	if len(got) != 1 {
		t.Fatalf("poll = %d", len(got))
	}
	eg := egressOf(t, got[0].Payload)
	if eg == nil || eg.PoolID != seg.ID.String() || eg.AppliesTo != proxypool.AppliesAll || len(eg.Endpoints) != 2 {
		t.Fatalf("egress = %+v", eg)
	}
	dead := eg.Endpoints[0].ID
	report := map[string]any{"pool_id": seg.ID.String(), "endpoints": []map[string]any{
		{"endpoint_id": dead, "proxy_down": 5, "last_error": "proxy_down: dial tcp 10.9.0.1:1080: connection refused"},
		{"endpoint_id": eg.Endpoints[1].ID, "ok": 30, "handshake_ms_p95": 80},
	}}
	path := "/api/v2/sensor/commands/" + id + "/" + protov2.EgressReportAction
	for i := 0; i < 3; i++ {
		resp, raw := h.call(s.key, http.MethodPost, path, report, protov2.HeaderLeaseEpoch, strconv.Itoa(got[0].LeaseEpoch))
		h.want(resp, raw, http.StatusNoContent, "")
	}
	var state, lastErr string
	if err := h.db.QueryRow(`SELECT state, last_error FROM proxy_endpoints WHERE id = $1`, dead).Scan(&state, &lastErr); err != nil {
		t.Fatal(err)
	}
	if state != proxypool.StateQuarantined || !strings.Contains(lastErr, "connection refused") {
		t.Fatalf("dead endpoint: %s %q", state, lastErr)
	}
	if err := h.db.QueryRow(`SELECT state FROM proxy_endpoints WHERE id = $1`, eg.Endpoints[1].ID).Scan(&state); err != nil || state != proxypool.StateHealthy {
		t.Fatalf("live endpoint: %s %v", state, err)
	}
	// The next job leaves the quarantined endpoint out.
	h.newCommand(h.tenantID, s.id)
	next := h.pollClaim(s)
	if len(next) != 1 {
		t.Fatalf("poll = %d", len(next))
	}
	if eg := egressOf(t, next[0].Payload); eg == nil || len(eg.Endpoints) != 1 || eg.Endpoints[0].ID == dead {
		t.Fatalf("next job egress = %+v", eg)
	}
	// Another tenant's sensor cannot report on this pool.
	tenantB := h.newTenant()
	sB := h.newSensor(tenantB, "egress-b")
	resp, _ := h.call(sB.key, http.MethodPost, path, report, protov2.HeaderLeaseEpoch, strconv.Itoa(got[0].LeaseEpoch))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant report = %d", resp.StatusCode)
	}
	// The sensor cannot move the health of a pool of its own organization
	// that its jobs do not use (the default pool here).
	def, err := h.egress.ListPools(context.Background(), h.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range def {
		if !p.IsDefault {
			continue
		}
		other := map[string]any{"pool_id": p.ID.String(), "endpoints": []map[string]any{
			{"endpoint_id": p.Endpoints[0].ID.String(), "proxy_auth": 1},
		}}
		resp, raw := h.call(s.key, http.MethodPost, path, other, protov2.HeaderLeaseEpoch, strconv.Itoa(got[0].LeaseEpoch))
		h.want(resp, raw, http.StatusNotFound, "")
		var st string
		if err := h.db.QueryRow(`SELECT state FROM proxy_endpoints WHERE id = $1`, p.Endpoints[0].ID.String()).Scan(&st); err != nil || st == proxypool.StateQuarantined {
			t.Fatalf("unused pool endpoint: %s %v", st, err)
		}
	}
	// A report long after the job ended is refused.
	if _, err := h.db.Exec(`UPDATE commands SET status = 'completed', completed_at = now() - interval '1 hour' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	resp, raw := h.call(s.key, http.MethodPost, path, report, protov2.HeaderLeaseEpoch, strconv.Itoa(got[0].LeaseEpoch))
	h.want(resp, raw, http.StatusNotFound, "")
}

func mustID(t *testing.T, s string) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (h *ctlHarness) newValidateCommand(tenantID, sensorID string) string {
	h.t.Helper()
	c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: tenantID, SensorID: sensorID,
		Type: "validate", Priority: "normal", Payload: json.RawMessage(`{"target":{"address":"203.0.113.9:443"},"executor_kind":"safe-check"}`), ExpiresIn: 3600})
	if err != nil {
		h.t.Fatalf("create validate command: %v", err)
	}
	return c.ID.String()
}

// SECURITY (egress leak): a validate job probes its target. A sensor whose
// jobs use a pool gets one only when its validate executor reports that it
// honors the pool (egress.validate@1), and then the job carries the pool;
// an older sensor would probe from its own address, so the job waits.
func TestProxyEgress_ValidateJobsNeverGoDirect(t *testing.T) {
	h := newCtlHarnessWith(t, true)
	s := h.newSensor(h.tenantID, "egress-validate")
	h.reportCaps(s, "validate", "net.confined@1", "egress.upstream@1")
	pool := h.newPool(h.tenantID, "corp", "http://10.0.0.6:3128", true)
	id := h.newValidateCommand(h.tenantID, s.id)

	if got := h.pollClaim(s); len(got) != 0 {
		t.Fatalf("a sensor whose validate jobs would go direct got %d job(s)", len(got))
	}
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("claim by id = %d %s, want 409", resp.StatusCode, raw)
	}
	var status string
	if err := h.db.QueryRow(`SELECT status FROM commands WHERE id = $1`, id).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("command %s after a refused claim (%v)", status, err)
	}

	// A sensor that routes validate jobs through the pool gets it, with
	// the pool.
	h.reportCaps(s, "validate", "net.confined@1", "egress.upstream@1", "egress.validate@1")
	got := h.pollClaim(s)
	if len(got) != 1 || got[0].ID != id {
		t.Fatalf("poll = %+v", got)
	}
	if eg := egressOf(t, got[0].Payload); eg == nil || eg.PoolID != pool.ID.String() || len(eg.Endpoints) != 1 {
		t.Fatalf("validate job egress = %+v", eg)
	}

	// The validate capability alone, without confinement, is not enough.
	other := h.newSensor(h.tenantID, "egress-validate-unconfined")
	h.reportCaps(other, "validate", "egress.validate@1")
	h.newValidateCommand(h.tenantID, other.id)
	if got := h.pollClaim(other); len(got) != 0 {
		t.Fatalf("an unconfined sensor got %d validate job(s)", len(got))
	}

	// Direct for a sensor: its validate jobs go out without a member, and
	// one a command's creator put in the payload is removed.
	if err := h.egress.AssignSensor(context.Background(), h.tenantID, other.id, proxypool.ModeDirect, "", auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`UPDATE commands SET payload = payload || '{"egress":{"mode":"pool","pool_id":"x","endpoints":[{"host":"203.0.113.9"}]}}'::jsonb WHERE sensor_id = $1`, other.id); err != nil {
		t.Fatal(err)
	}
	got = h.pollClaim(other)
	if len(got) != 1 || egressOf(t, got[0].Payload) != nil {
		t.Fatalf("direct sensor: %+v", got)
	}
}

// SECURITY (egress leak): disabling a pool that a sensor is assigned to
// never sends that sensor's scans direct: its jobs carry the pool with no
// endpoint, so the sensor fails them closed, and no credential is handed
// out. A disabled organization default is the "use proxies" switch: the
// sensors that inherit it scan directly.
func TestProxyEgress_DisabledAssignedPoolFailsClosed(t *testing.T) {
	h := newCtlHarnessWith(t, true)
	s := h.newSensor(h.tenantID, "egress-disabled")
	h.reportCaps(s, "net.confined@1", "egress.upstream@1")
	seg := h.newPool(h.tenantID, "segment", "socks5://bob:"+egressSecret+"@10.9.0.1:1080", false)
	if err := h.egress.AssignSensor(context.Background(), h.tenantID, s.id, proxypool.ModePool, seg.ID.String(), auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := h.egress.UpdatePool(context.Background(), proxypoolapp.UpdatePoolInput{TenantID: h.tenantID, PoolID: seg.ID.String(), Enabled: &off},
		auditapp.AuditContext{TenantID: h.tenantID}); err != nil {
		t.Fatal(err)
	}
	id := h.newCommand(h.tenantID, s.id)
	got := h.pollClaim(s)
	if len(got) != 1 {
		t.Fatalf("poll = %d", len(got))
	}
	eg := egressOf(t, got[0].Payload)
	if eg == nil || eg.PoolID != seg.ID.String() || eg.AppliesTo != proxypool.AppliesAll || eg.Endpoints == nil || len(eg.Endpoints) != 0 {
		t.Fatalf("disabled assigned pool: egress = %+v (want the pool with no endpoint)", eg)
	}
	credPath := "/api/v2/sensor/commands/" + id + "/" + protov2.EgressCredentialsAction
	resp, raw := h.call(s.key, http.MethodPost, credPath, map[string]any{"pool_id": seg.ID.String()},
		protov2.HeaderLeaseEpoch, strconv.Itoa(got[0].LeaseEpoch))
	h.want(resp, raw, 200, "")
	if creds := decodeAs[protov2.EgressCredentialsResponse](t, raw); len(creds.Credentials) != 0 || strings.Contains(string(raw), egressSecret) {
		t.Fatalf("credentials of a disabled pool: %s", raw)
	}

	// A disabled default: inheriting sensors scan directly.
	inherit := h.newSensor(h.tenantID, "egress-inherit")
	h.reportCaps(inherit, "net.confined@1", "egress.upstream@1")
	def := false
	if _, err := h.egress.CreatePool(context.Background(), proxypoolapp.CreatePoolInput{TenantID: h.tenantID, Name: "default",
		IsDefault: true, Enabled: &def}, auditapp.AuditContext{TenantID: h.tenantID}); err != nil {
		t.Fatal(err)
	}
	h.newCommand(h.tenantID, inherit.id)
	got = h.pollClaim(inherit)
	if len(got) != 1 || egressOf(t, got[0].Payload) != nil {
		t.Fatalf("disabled default: %+v", got)
	}
}

// The Test button, sensor side: a proxy_test command carries the pool's
// endpoints of a draft (disabled, unassigned) pool; the sensor that holds its
// lease gets exactly that pool's credentials, its egress report moves that
// pool's health (wrong credentials quarantine, a pass lifts a quarantine to
// probation), and what it completes with is read back sanitized. Another
// sensor, another tenant, another pool and a lease that is gone get
// not found.
func TestProxyTest_SensorSideCredentialsReportAndResult(t *testing.T) {
	h := newCtlHarnessWith(t, true)
	s := h.newSensor(h.tenantID, "test-runner")
	h.reportCaps(s, "net.confined@1", "egress.upstream@1", "proxy.test@1")
	if _, err := h.db.Exec(`UPDATE sensors SET health = 'online' WHERE id = $1`, s.id); err != nil {
		t.Fatal(err)
	}
	bystander := h.newSensor(h.tenantID, "bystander")
	h.reportCaps(bystander, "net.confined@1", "egress.upstream@1", "proxy.test@1")

	// A draft pool: disabled, assigned to nobody, with credentials.
	draft := h.newPool(h.tenantID, "draft", "socks5://alice:"+egressSecret+"@10.0.0.5:1080#dc1\nhttp://10.0.0.6:3128", false)
	if _, err := h.db.Exec(`UPDATE proxy_pools SET enabled = false WHERE id = $1`, draft.ID.String()); err != nil {
		t.Fatal(err)
	}
	other := h.newPool(h.tenantID, "other", "http://10.7.0.1:3128", false)

	handles, err := h.egress.RequestTest(context.Background(), proxypoolapp.TestRequest{TenantID: h.tenantID, PoolID: draft.ID.String(),
		SensorIDs: []string{s.id}}, auditapp.AuditContext{TenantID: h.tenantID})
	if err != nil {
		t.Fatal(err)
	}
	id := handles[0].CommandID

	got := h.pollClaim(s)
	if len(got) != 1 || got[0].ID != id || got[0].Type != "proxy_test" {
		t.Fatalf("poll = %+v", got)
	}
	if strings.Contains(string(got[0].Payload), egressSecret) || strings.Contains(string(got[0].Payload), "alice") {
		t.Fatalf("credentials in the test command: %s", got[0].Payload)
	}
	// Another sensor of the tenant does not get a command pinned to s.
	if other := h.pollClaim(bystander); len(other) != 0 {
		t.Fatalf("the bystander got %d command(s)", len(other))
	}
	eg := egressOf(t, got[0].Payload)
	if eg == nil || eg.PoolID != draft.ID.String() || eg.AppliesTo != proxypool.AppliesAll || len(eg.Endpoints) != 2 {
		t.Fatalf("egress %+v", eg)
	}
	epoch := strconv.Itoa(got[0].LeaseEpoch)
	credPath := "/api/v2/sensor/commands/" + id + "/" + protov2.EgressCredentialsAction

	// The credentials of the draft pool, though no sensor's jobs use it.
	resp, raw := h.call(s.key, http.MethodPost, credPath, map[string]any{"pool_id": draft.ID.String()}, protov2.HeaderLeaseEpoch, epoch)
	h.want(resp, raw, 200, "")
	creds := decodeAs[protov2.EgressCredentialsResponse](t, raw)
	if len(creds.Credentials) != 1 || creds.Credentials[0].Username != "alice" || creds.Credentials[0].Password != egressSecret {
		t.Fatalf("credentials %+v", creds)
	}
	for name, call := range map[string]func() (*http.Response, []byte){
		"another pool of the organization": func() (*http.Response, []byte) {
			return h.call(s.key, http.MethodPost, credPath, map[string]any{"pool_id": other.ID.String()}, protov2.HeaderLeaseEpoch, epoch)
		},
		"the bystander": func() (*http.Response, []byte) {
			return h.call(bystander.key, http.MethodPost, credPath, map[string]any{"pool_id": draft.ID.String()}, protov2.HeaderLeaseEpoch, epoch)
		},
		"no lease epoch": func() (*http.Response, []byte) {
			return h.call(s.key, http.MethodPost, credPath, map[string]any{"pool_id": draft.ID.String()})
		},
	} {
		resp, raw := call()
		if resp.StatusCode != http.StatusNotFound || strings.Contains(string(raw), egressSecret) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, raw)
		}
	}
	tenantB := h.newTenant()
	sB := h.newSensor(tenantB, "test-b")
	resp, raw = h.call(sB.key, http.MethodPost, credPath, map[string]any{"pool_id": draft.ID.String()}, protov2.HeaderLeaseEpoch, epoch)
	if resp.StatusCode != http.StatusNotFound || strings.Contains(string(raw), egressSecret) {
		t.Fatalf("cross-tenant: %d %s", resp.StatusCode, raw)
	}

	// The report: wrong credentials quarantine the draft pool's endpoint,
	// a pass on the other endpoint keeps it out of quarantine; a report on
	// another pool is refused.
	reportPath := "/api/v2/sensor/commands/" + id + "/" + protov2.EgressReportAction
	e0, e1 := eg.Endpoints[0].ID, eg.Endpoints[1].ID
	resp, raw = h.call(s.key, http.MethodPost, reportPath, map[string]any{"pool_id": draft.ID.String(), "endpoints": []map[string]any{
		{"endpoint_id": e0, "proxy_auth": 1, "last_error": "proxy_auth: proxy refused the credentials"},
		{"endpoint_id": e1, "ok": 1, "handshake_ms_p95": 90},
	}}, protov2.HeaderLeaseEpoch, epoch)
	h.want(resp, raw, http.StatusNoContent, "")
	var state string
	if err := h.db.QueryRow(`SELECT state FROM proxy_endpoints WHERE id = $1`, e0).Scan(&state); err != nil || state != proxypool.StateQuarantined {
		t.Fatalf("wrong credentials: %s %v", state, err)
	}
	if err := h.db.QueryRow(`SELECT state FROM proxy_endpoints WHERE id = $1`, e1).Scan(&state); err != nil || state == proxypool.StateQuarantined {
		t.Fatalf("a passing endpoint: %s %v", state, err)
	}
	// A later test that passes lifts the quarantine to probation.
	resp, raw = h.call(s.key, http.MethodPost, reportPath, map[string]any{"pool_id": draft.ID.String(), "endpoints": []map[string]any{
		{"endpoint_id": e0, "ok": 1, "handshake_ms_p95": 70},
	}}, protov2.HeaderLeaseEpoch, epoch)
	h.want(resp, raw, http.StatusNoContent, "")
	if err := h.db.QueryRow(`SELECT state FROM proxy_endpoints WHERE id = $1`, e0).Scan(&state); err != nil || state != proxypool.StateProbation {
		t.Fatalf("a passing test after a quarantine: %s %v", state, err)
	}
	resp, raw = h.call(s.key, http.MethodPost, reportPath, map[string]any{"pool_id": other.ID.String(), "endpoints": []map[string]any{
		{"endpoint_id": other.Endpoints[0].ID.String(), "proxy_auth": 1},
	}}, protov2.HeaderLeaseEpoch, epoch)
	h.want(resp, raw, http.StatusNotFound, "")
	if err := h.db.QueryRow(`SELECT state FROM proxy_endpoints WHERE id = $1`, other.Endpoints[0].ID.String()).Scan(&state); err != nil || state == proxypool.StateQuarantined {
		t.Fatalf("another pool's endpoint moved: %s %v", state, err)
	}

	// The echo answers while the test is live, for its token only.
	var payload struct {
		Echo struct{ URL, Nonce string } `json:"echo"`
	}
	if err := json.Unmarshal(got[0].Payload, &payload); err != nil || payload.Echo.Nonce == "" {
		t.Fatalf("echo in the payload: %s", got[0].Payload)
	}

	// Complete with a hostile result: it is read back cut to the pool.
	base := "/api/v2/sensor/commands/" + id
	resp, raw = h.call(s.key, http.MethodPost, base+"/start", nil, protov2.HeaderLeaseEpoch, epoch)
	h.want(resp, raw, 200, "")
	result := map[string]any{"status": "completed", "metadata": map[string]any{"proxy_test": map[string]any{
		"pool_id": draft.ID.String(), "endpoints": []map[string]any{
			{"endpoint_id": e0, "ok": true, "handshake_ms": 90, "exit_ip": "203.0.113.9", "families": []string{"v4"}},
			{"endpoint_id": e1, "ok": false, "class": "proxy_down", "error": "http://u:hunter2@10.0.0.6:3128 refused"},
			{"endpoint_id": other.Endpoints[0].ID.String(), "ok": true, "exit_ip": "198.51.100.7"},
		}}}}
	resp, raw = h.call(s.key, http.MethodPost, base+"/complete", map[string]any{"result": result}, protov2.HeaderLeaseEpoch, epoch)
	h.want(resp, raw, 200, "")
	out, err := h.egress.TestResults(context.Background(), h.tenantID, draft.ID.String(), []string{id})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Status != "completed" || len(out[0].Results) != 2 || out[0].Results[0].ExitIP != "203.0.113.9" ||
		out[0].Results[1].Class != "proxy_down" || strings.Contains(out[0].Results[1].Error, "hunter2") {
		t.Fatalf("results %+v", out)
	}
	// Tenant B cannot read it through its own pool or ours.
	if _, err := h.egress.TestResults(context.Background(), tenantB, draft.ID.String(), []string{id}); err == nil {
		t.Fatal("another tenant read the test")
	}
	// After the end the echo no longer answers and credentials are not served.
	resp, raw = h.call(s.key, http.MethodPost, credPath, map[string]any{"pool_id": draft.ID.String()}, protov2.HeaderLeaseEpoch, epoch)
	h.want(resp, raw, http.StatusNotFound, "")
	if h.egress.VerifyTestEcho(context.Background(), h.tenantID, id, payload.Echo.Nonce) {
		t.Fatal("the echo answers for an ended test")
	}
}

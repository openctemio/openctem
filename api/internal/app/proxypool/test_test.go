package proxypool

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	pooldom "github.com/openctemio/openctem/api/pkg/domain/proxypool"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type testSensorStore struct{ byID map[string]*sensordom.Sensor }

func (f *testSensorStore) GetByTenantAndID(_ context.Context, tenant, id shared.ID) (*sensordom.Sensor, error) {
	sn, ok := f.byID[id.String()]
	// Tenant-scoped like the repository: another organization's sensor, and
	// a shared sensor looked up under a tenant, do not exist.
	if !ok || sn.TenantID == nil || *sn.TenantID != tenant {
		if ok && sn.IsShared() {
			return sn, nil
		}
		return nil, shared.ErrNotFound
	}
	return sn, nil
}

type testCommandStore struct{ cmds []*commanddom.Command }

func (f *testCommandStore) Create(_ context.Context, c *commanddom.Command) error {
	f.cmds = append([]*commanddom.Command{c}, f.cmds...)
	return nil
}
func (f *testCommandStore) GetByTenantAndID(_ context.Context, tenant, id shared.ID) (*commanddom.Command, error) {
	for _, c := range f.cmds {
		if c.ID == id && c.TenantID == tenant {
			return c, nil
		}
	}
	return nil, shared.ErrNotFound
}
func (f *testCommandStore) List(_ context.Context, flt commanddom.Filter, _ pagination.Pagination) (pagination.Result[*commanddom.Command], error) {
	var out []*commanddom.Command
	for _, c := range f.cmds {
		if flt.TenantID != nil && c.TenantID != *flt.TenantID {
			continue
		}
		if flt.Type != nil && c.Type != *flt.Type {
			continue
		}
		out = append(out, c)
	}
	return pagination.Result[*commanddom.Command]{Data: out}, nil
}

type testAudit struct{ events []auditapp.AuditEvent }

func (a *testAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.events = append(a.events, ev)
	return nil
}

type testFixture struct {
	svc      *Service
	repo     *fakeRepo
	sensors  *testSensorStore
	commands *testCommandStore
	audit    *testAudit
	tenant   shared.ID
	pool     *pooldom.Pool
	now      time.Time
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	repo := newFakeRepo()
	enc, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc, tenant := NewService(repo, enc, nil, logger.NewNop()), shared.NewID().String()
	f := &testFixture{svc: svc, repo: repo, sensors: &testSensorStore{byID: map[string]*sensordom.Sensor{}},
		commands: &testCommandStore{}, audit: &testAudit{}, tenant: shared.MustIDFromString(tenant), now: time.Now()}
	svc.audit = f.audit
	svc.now = func() time.Time { return f.now }
	svc.EnableTest(f.sensors, f.commands, TestConfig{EchoBase: "https://api.example.net/", AltPort: 80})
	// A disabled, unassigned pool (the draft flow) with two endpoints.
	p, err := svc.CreatePool(context.Background(), CreatePoolInput{TenantID: tenant, Name: "draft", Enabled: b(false),
		EndpointsText: s("socks5://alice:s3cret-pw@10.0.0.5:1080#dc1\nhttp://10.0.0.6:3128\n")}, auditapp.AuditContext{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	f.pool = repo.pools[key(p.TenantID, p.ID)]
	return f
}

func (f *testFixture) sensor(t *testing.T, tenant shared.ID, mut ...func(*sensordom.Sensor)) *sensordom.Sensor {
	t.Helper()
	sn := &sensordom.Sensor{ID: shared.NewID(), TenantID: &tenant, Name: "sensor-" + shared.NewID().String()[:4],
		Status: sensordom.SensorStatusActive, Health: sensordom.SensorHealthOnline, Scope: sensordom.ScopeOrganization}
	sn.Reported.Capabilities = []string{sensordom.CapabilityProxyTest}
	for _, m := range mut {
		m(sn)
	}
	f.sensors.byID[sn.ID.String()] = sn
	return sn
}

func (f *testFixture) request(ids ...string) ([]TestHandle, error) {
	return f.svc.RequestTest(context.Background(), TestRequest{TenantID: f.tenant.String(), PoolID: f.pool.ID.String(), SensorIDs: ids},
		auditapp.AuditContext{TenantID: f.tenant.String()})
}

func TestRequestTestQueuesAPinnedCommandPerSensorAndAudits(t *testing.T) {
	f := newTestFixture(t)
	a, c := f.sensor(t, f.tenant), f.sensor(t, f.tenant)
	got, err := f.request(a.ID.String(), c.ID.String(), a.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(f.commands.cmds) != 2 {
		t.Fatalf("handles %v commands %d", got, len(f.commands.cmds))
	}
	cmd := f.commands.cmds[1] // created first
	if cmd.Type != commanddom.CommandTypeProxyTest || cmd.SensorID == nil || *cmd.SensorID != a.ID || cmd.TenantID != f.tenant {
		t.Fatalf("command %+v", cmd)
	}
	if cmd.ExpiresAt == nil || cmd.ExpiresAt.After(f.now.Add(TestCommandTTL+time.Second)) {
		t.Fatalf("expiry %v", cmd.ExpiresAt)
	}
	// SECURITY: no credential, user name or password in the payload; every
	// endpoint is in it though the pool is disabled; it applies to all.
	for _, secret := range []string{"s3cret-pw", "alice"} {
		if strings.Contains(string(cmd.Payload), secret) {
			t.Fatalf("%q in the payload: %s", secret, cmd.Payload)
		}
	}
	var p testPayload
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Egress.PoolID != f.pool.ID.String() || p.Egress.AppliesTo != pooldom.AppliesAll || len(p.Egress.Endpoints) != 2 ||
		!p.Egress.Endpoints[0].Auth || p.Egress.Endpoints[1].Auth || p.Egress.Endpoints[0].Weight != 1 {
		t.Fatalf("egress %+v", p.Egress)
	}
	if len(p.Echo.Nonce) != 32 || !strings.HasPrefix(p.Echo.URL, "https://api.example.net"+testEchoPath+TestEchoToken(f.tenant.String(), cmd.ID.String(), p.Echo.Nonce)) || p.Echo.AltPort != 80 {
		t.Fatalf("echo %+v", p.Echo)
	}
	// Each command has its own token.
	var q testPayload
	_ = json.Unmarshal(f.commands.cmds[0].Payload, &q)
	if q.Echo.Nonce == p.Echo.Nonce {
		t.Fatal("two tests share a token")
	}
	n := 0
	for _, ev := range f.audit.events {
		if ev.Action == auditdom.ActionProxyPoolTestRequested {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("audit events %d", n)
	}
}

func TestRequestTestRefusals(t *testing.T) {
	f := newTestFixture(t)
	other := shared.NewID()
	otherSensor := f.sensor(t, other)
	shared1 := f.sensor(t, f.tenant, func(sn *sensordom.Sensor) { sn.Scope = sensordom.ScopeInstance; sn.TenantID = nil })
	offline := f.sensor(t, f.tenant, func(sn *sensordom.Sensor) { sn.Health = sensordom.SensorHealthOffline })
	disabled := f.sensor(t, f.tenant, func(sn *sensordom.Sensor) { sn.Status = sensordom.SensorStatusDisabled })
	old := f.sensor(t, f.tenant, func(sn *sensordom.Sensor) { sn.Reported.Capabilities = []string{sensordom.CapabilityEgressUpstream} })
	good := f.sensor(t, f.tenant)

	cases := map[string]struct {
		ids  []string
		want error
	}{
		"another organization's sensor is not found": {[]string{otherSensor.ID.String()}, pooldom.ErrSensorNotFound},
		"not a sensor id":               {[]string{"nope"}, pooldom.ErrSensorNotFound},
		"a shared sensor":               {[]string{shared1.ID.String()}, pooldom.ErrSensorNotFound},
		"an offline sensor":             {[]string{offline.ID.String()}, ErrTestSensorOffline},
		"a disabled sensor":             {[]string{disabled.ID.String()}, ErrTestSensorOffline},
		"a sensor without proxy.test@1": {[]string{old.ID.String()}, ErrTestSensorUnsupported},
		"no sensor":                     {nil, ErrTestSensors},
		"four sensors": {[]string{good.ID.String(), f.sensor(t, f.tenant).ID.String(), f.sensor(t, f.tenant).ID.String(),
			f.sensor(t, f.tenant).ID.String()}, ErrTestSensors},
		// One bad sensor in a good list queues nothing.
		"good and foreign": {[]string{good.ID.String(), otherSensor.ID.String()}, pooldom.ErrSensorNotFound},
	}
	for name, c := range cases {
		if _, err := f.request(c.ids...); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if len(f.commands.cmds) != 0 {
		t.Fatalf("a refused request queued %d command(s)", len(f.commands.cmds))
	}
}

func TestRequestTestPoolAndEchoRules(t *testing.T) {
	f := newTestFixture(t)
	sn := f.sensor(t, f.tenant)
	// Another organization's pool is not found.
	_, err := f.svc.RequestTest(context.Background(), TestRequest{TenantID: shared.NewID().String(), PoolID: f.pool.ID.String(),
		SensorIDs: []string{sn.ID.String()}}, auditapp.AuditContext{})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant pool: %v", err)
	}
	// A pool with nothing to test.
	empty, err := f.svc.CreatePool(context.Background(), CreatePoolInput{TenantID: f.tenant.String(), Name: "empty", Enabled: b(false)},
		auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.RequestTest(context.Background(), TestRequest{TenantID: f.tenant.String(), PoolID: empty.ID.String(),
		SensorIDs: []string{sn.ID.String()}}, auditapp.AuditContext{})
	if !errors.Is(err, ErrTestNoEndpoint) {
		t.Fatalf("empty pool: %v", err)
	}
	// No https address for the echo: unavailable, nothing queued.
	f.svc.EnableTest(f.sensors, f.commands, TestConfig{})
	if _, err := f.request(sn.ID.String()); !errors.Is(err, ErrTestUnavailable) {
		t.Fatalf("no echo: %v", err)
	}
	if len(f.commands.cmds) != 0 {
		t.Fatal("queued without an echo")
	}
}

func TestRequestTestIsLimitedToOnePerPoolPerMinute(t *testing.T) {
	f := newTestFixture(t)
	sn := f.sensor(t, f.tenant)
	if _, err := f.request(sn.ID.String()); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(30 * time.Second)
	if _, err := f.request(sn.ID.String()); !errors.Is(err, ErrTestRateLimited) {
		t.Fatalf("second test within a minute: %v", err)
	}
	// Another pool of the tenant is not limited by this one.
	p2, err := f.svc.CreatePool(context.Background(), CreatePoolInput{TenantID: f.tenant.String(), Name: "second", Enabled: b(false),
		EndpointsText: s(oneProxy)}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RequestTest(context.Background(), TestRequest{TenantID: f.tenant.String(), PoolID: p2.ID.String(),
		SensorIDs: []string{sn.ID.String()}}, auditapp.AuditContext{}); err != nil {
		t.Fatalf("another pool: %v", err)
	}
	f.now = f.now.Add(40 * time.Second)
	if _, err := f.request(sn.ID.String()); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func finish(t *testing.T, c *commanddom.Command, result any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"status": "completed", "metadata": map[string]any{"proxy_test": result}})
	if err != nil {
		t.Fatal(err)
	}
	c.Status = commanddom.CommandStatusCompleted
	c.Result = raw
	now := time.Now()
	c.CompletedAt = &now
}

// SECURITY: what a sensor reports is cut to a closed set; endpoints that are
// not in the pool, classes and families it made up, an exit "address" that
// is not one and long or credential-bearing text do not pass.
func TestTestResultsAreSanitizedAndScopedToThePool(t *testing.T) {
	f := newTestFixture(t)
	sn := f.sensor(t, f.tenant)
	handles, err := f.request(sn.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	cmd := f.commands.cmds[0]
	e0, e1 := f.pool.Endpoints[0].ID.String(), f.pool.Endpoints[1].ID.String()

	// Pending until the sensor finishes.
	out, err := f.svc.TestResults(context.Background(), f.tenant.String(), f.pool.ID.String(), []string{handles[0].CommandID})
	if err != nil || len(out) != 1 || out[0].Status != "pending" || out[0].SensorName != sn.Name || len(out[0].Results) != 0 {
		t.Fatalf("pending: %+v %v", out, err)
	}

	yes := true
	finish(t, cmd, []map[string]any{}) // placeholder, replaced below
	raw, _ := json.Marshal(map[string]any{"status": "completed", "metadata": map[string]any{"proxy_test": map[string]any{
		"pool_id": f.pool.ID.String(),
		"endpoints": []map[string]any{
			{"endpoint_id": e0, "ok": true, "handshake_ms": 120, "exit_ip": "203.0.113.9", "families": []string{"v4", "v6", "v9"}, "port_restricted": &yes},
			{"endpoint_id": e1, "ok": true, "class": "proxy_auth", "handshake_ms": -5, "exit_ip": "<script>", "error": "socks5://bob:hunter2@10.0.0.6:1080 refused\nsecond line"},
			{"endpoint_id": shared.NewID().String(), "ok": true, "exit_ip": "198.51.100.1"}, // not in the pool
			{"endpoint_id": e0, "ok": true}, // a repeat
		}}}})
	cmd.Result = raw
	out, err = f.svc.TestResults(context.Background(), f.tenant.String(), f.pool.ID.String(), []string{handles[0].CommandID})
	if err != nil {
		t.Fatal(err)
	}
	r := out[0].Results
	if out[0].Status != "completed" || len(r) != 2 {
		t.Fatalf("results %+v", out[0])
	}
	if !r[0].OK || r[0].ExitIP != "203.0.113.9" || len(r[0].Families) != 2 || r[0].PortRestricted == nil || !*r[0].PortRestricted ||
		r[0].Address != "socks5://10.0.0.5:1080" || r[0].HandshakeMs != 120 {
		t.Fatalf("first %+v", r[0])
	}
	if r[1].OK || r[1].Class != "proxy_auth" || r[1].ExitIP != "" || r[1].HandshakeMs != 0 || r[1].PortRestricted != nil {
		t.Fatalf("second %+v", r[1])
	}
	if strings.Contains(r[1].Error, "hunter2") || strings.Contains(r[1].Error, "bob") || strings.Contains(r[1].Error, "\n") {
		t.Fatalf("credentials or newline in the error: %q", r[1].Error)
	}
}

func TestTestResultsStayInsideTheTenantAndThePool(t *testing.T) {
	f := newTestFixture(t)
	sn := f.sensor(t, f.tenant)
	handles, err := f.request(sn.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	// Another organization cannot read the test, with its own pool or not.
	otherTenant := shared.NewID().String()
	op, err := f.svc.CreatePool(context.Background(), CreatePoolInput{TenantID: otherTenant, Name: "theirs", Enabled: b(false),
		EndpointsText: s(oneProxy)}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ tenant, pool string }{
		"other tenant, our pool":   {otherTenant, f.pool.ID.String()},
		"other tenant, their pool": {otherTenant, op.ID.String()},
		"our tenant, their pool":   {f.tenant.String(), op.ID.String()},
	} {
		if _, err := f.svc.TestResults(context.Background(), c.tenant, c.pool, []string{handles[0].CommandID}); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Our other pool: the command names the first one.
	p2, _ := f.svc.CreatePool(context.Background(), CreatePoolInput{TenantID: f.tenant.String(), Name: "second", Enabled: b(false)}, auditapp.AuditContext{})
	if _, err := f.svc.TestResults(context.Background(), f.tenant.String(), p2.ID.String(), []string{handles[0].CommandID}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("another pool of the tenant: %v", err)
	}
	// A command that is not a test is not found.
	scan, _ := commanddom.NewCommand(f.tenant, commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, json.RawMessage(`{"pool_id":"`+f.pool.ID.String()+`"}`))
	_ = f.commands.Create(context.Background(), scan)
	if _, err := f.svc.TestResults(context.Background(), f.tenant.String(), f.pool.ID.String(), []string{scan.ID.String()}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a scan command: %v", err)
	}
}

func TestVerifyTestEchoNeedsALiveCommandAndItsToken(t *testing.T) {
	f := newTestFixture(t)
	sn := f.sensor(t, f.tenant)
	if _, err := f.request(sn.ID.String()); err != nil {
		t.Fatal(err)
	}
	cmd := f.commands.cmds[0]
	var p testPayload
	_ = json.Unmarshal(cmd.Payload, &p)
	verify := func(tenant shared.ID, id, nonce string) bool {
		return f.svc.VerifyTestEcho(context.Background(), tenant.String(), id, nonce)
	}
	// Pending: no sensor has taken it yet.
	if verify(f.tenant, cmd.ID.String(), p.Echo.Nonce) {
		t.Fatal("echo answered for a pending test")
	}
	cmd.Status = commanddom.CommandStatusRunning
	if !verify(f.tenant, cmd.ID.String(), p.Echo.Nonce) {
		t.Fatal("echo refused its own token")
	}
	wrong := strings.Repeat("0", 32)
	for name, ok := range map[string]bool{
		"wrong token":     verify(f.tenant, cmd.ID.String(), wrong),
		"short token":     verify(f.tenant, cmd.ID.String(), "abc"),
		"other tenant":    verify(shared.NewID(), cmd.ID.String(), p.Echo.Nonce),
		"unknown command": verify(f.tenant, shared.NewID().String(), p.Echo.Nonce),
		"not an id":       verify(f.tenant, "x", p.Echo.Nonce),
	} {
		if ok {
			t.Errorf("%s: echo answered", name)
		}
	}
	cmd.Status = commanddom.CommandStatusCompleted
	if verify(f.tenant, cmd.ID.String(), p.Echo.Nonce) {
		t.Fatal("echo answered after the test ended")
	}
	// A scan command carrying the same nonce is no test.
	scan, _ := commanddom.NewCommand(f.tenant, commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, cmd.Payload)
	scan.Status = commanddom.CommandStatusRunning
	_ = f.commands.Create(context.Background(), scan)
	if verify(f.tenant, scan.ID.String(), p.Echo.Nonce) {
		t.Fatal("echo answered for a scan command")
	}
}

func TestTestCredentialsAndReportAreBoundToTheCommandsPool(t *testing.T) {
	f := newTestFixture(t)
	sn := f.sensor(t, f.tenant)
	if _, err := f.request(sn.ID.String()); err != nil {
		t.Fatal(err)
	}
	cmd := f.commands.cmds[0]
	other, err := f.svc.CreatePool(context.Background(), CreatePoolInput{TenantID: f.tenant.String(), Name: "other", Enabled: b(false),
		EndpointsText: s(oneProxy)}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	// Another pool of the same organization: not found, for credentials and
	// for the health report.
	if _, err := f.svc.TestCredentialsFor(context.Background(), cmd, other.ID.String()); !errors.Is(err, pooldom.ErrPoolNotFound) {
		t.Fatalf("credentials of another pool: %v", err)
	}
	if err := f.svc.ApplyTestReport(context.Background(), cmd, sn.ID, Report{PoolID: other.ID.String(),
		Endpoints: map[string]pooldom.Signal{other.Endpoints[0].ID.String(): {ProxyAuth: 1}}}); !errors.Is(err, pooldom.ErrPoolNotFound) {
		t.Fatalf("report on another pool: %v", err)
	}
	// A command that is not a test names no pool.
	scan, _ := commanddom.NewCommand(f.tenant, commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, cmd.Payload)
	if _, err := f.svc.TestCredentialsFor(context.Background(), scan, f.pool.ID.String()); !errors.Is(err, pooldom.ErrPoolNotFound) {
		t.Fatalf("credentials for a scan command: %v", err)
	}
}

func TestOnProxyTestFinishedAuditsCountsOnly(t *testing.T) {
	f := newTestFixture(t)
	sn := f.sensor(t, f.tenant)
	if _, err := f.request(sn.ID.String()); err != nil {
		t.Fatal(err)
	}
	cmd := f.commands.cmds[0]
	e0, e1 := f.pool.Endpoints[0].ID.String(), f.pool.Endpoints[1].ID.String()
	finish(t, cmd, map[string]any{"pool_id": f.pool.ID.String(), "endpoints": []map[string]any{
		{"endpoint_id": e0, "ok": true, "exit_ip": "203.0.113.9"},
		{"endpoint_id": e1, "ok": false, "class": "proxy_auth"},
	}})
	f.audit.events = nil
	f.svc.OnProxyTestFinished(context.Background(), cmd)
	if len(f.audit.events) != 1 || f.audit.events[0].Action != auditdom.ActionProxyPoolTested {
		t.Fatalf("events %+v", f.audit.events)
	}
	ev := f.audit.events[0]
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), "203.0.113.9") || strings.Contains(string(raw), "10.0.0.5") {
		t.Fatalf("an address in the audit event: %s", raw)
	}
	if !strings.Contains(ev.Message, "1 of 2") {
		t.Fatalf("message %q", ev.Message)
	}
}

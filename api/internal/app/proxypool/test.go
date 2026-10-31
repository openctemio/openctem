package proxypool

// Testing a proxy pool (the Test button; docs/architecture/sensor-proxies.md).
//
// The platform never connects to a proxy: a customer's proxy is often on a
// private network, and a platform that dials arbitrary endpoints is an SSRF
// primitive. It asks up to three of the organization's online sensors to
// test every endpoint of the pool instead: a proxy_test command pinned to
// each sensor carries the endpoints (never credentials) and the platform's
// echo, and the sensor completes with one result per endpoint. Credentials
// are fetched by the sensor under the command's lease (TestCredentialsFor),
// and the sensor's attempts reach the endpoints' health through the normal
// egress report (ApplyTestReport), so a passing test moves a quarantined
// endpoint to probation and wrong credentials quarantine it, as for a scan.
//
// Everything a sensor reports back is untrusted: results are cut to a
// closed set of fields, classes and families, the exit address must parse,
// the error text is sanitized, and an endpoint that is not in the pool is
// dropped.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	pooldom "github.com/openctemio/openctem/api/pkg/domain/proxypool"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Limits of a test.
const (
	// TestMaxSensors is how many sensors one test may ask.
	TestMaxSensors = 3
	// TestRateWindow is the least time between two tests of one pool.
	TestRateWindow = time.Minute
	// TestCommandTTL is how long a sensor has to pick a test up.
	TestCommandTTL = 10 * time.Minute

	// testEchoPath is where the platform's echo answers (the sensor's
	// request carries the command's token in the path).
	testEchoPath = "/api/v1/proxy-test-echoes/"
)

// Errors of a test. The sentinels wrap a shared error so handlers map them.
var (
	ErrTestUnavailable = shared.NewDomainError("PROXY_TEST_UNAVAILABLE",
		"the proxy test is not available: the platform has no https address for the test echo (set PROXY_TEST_ECHO_URL)", shared.ErrConflict)
	ErrTestNoEndpoint = shared.NewDomainError("PROXY_TEST_NO_ENDPOINT",
		"the pool has no proxy to test: add at least one", shared.ErrValidation)
	ErrTestSensors = shared.NewDomainError("PROXY_TEST_SENSORS",
		fmt.Sprintf("choose between 1 and %d sensors to run the test", TestMaxSensors), shared.ErrValidation)
	ErrTestSensorOffline = shared.NewDomainError("PROXY_TEST_SENSOR_OFFLINE",
		"the sensor is not online", shared.ErrConflict)
	ErrTestSensorUnsupported = shared.NewDomainError("PROXY_TEST_SENSOR_UNSUPPORTED",
		"the sensor cannot test proxies (it does not report proxy.test@1: upgrade it, and check that it accepts platform proxy pools)", shared.ErrConflict)
	// ErrTestRateLimited: one test per pool per TestRateWindow.
	ErrTestRateLimited = errors.New("a proxy pool can be tested once a minute")
)

// TestSensors resolves a sensor inside one tenant (the sensor repository).
type TestSensors interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sensordom.Sensor, error)
}

// TestCommands creates and reads proxy_test commands (the command
// repository).
type TestCommands interface {
	Create(ctx context.Context, cmd *commanddom.Command) error
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*commanddom.Command, error)
	List(ctx context.Context, filter commanddom.Filter, page pagination.Pagination) (pagination.Result[*commanddom.Command], error)
}

// TestConfig is where tests connect.
type TestConfig struct {
	// EchoBase is the https origin of the platform's echo ("" disables
	// tests).
	EchoBase string
	// AltPort is the echo host's second port (0: not tried).
	AltPort int
}

type testSetup struct {
	sensors  TestSensors
	commands TestCommands
	cfg      TestConfig
	// mu serializes the rate check and the creation of one pool's tests
	// inside this process.
	mu sync.Mutex
}

// EnableTest wires the proxy test. Without it RequestTest answers
// ErrTestUnavailable.
func (s *Service) EnableTest(sensors TestSensors, commands TestCommands, cfg TestConfig) {
	cfg.EchoBase = strings.TrimRight(strings.TrimSpace(cfg.EchoBase), "/")
	s.test = &testSetup{sensors: sensors, commands: commands, cfg: cfg}
}

// TestHandle names one test command that was queued.
type TestHandle struct {
	SensorID   string
	SensorName string
	CommandID  string
}

// TestRequest asks sensors to test a pool.
type TestRequest struct {
	TenantID  string
	PoolID    string
	SensorIDs []string
}

// RequestTest queues a proxy_test command for each of the sensors. It
// refuses a sensor of another organization or a shared one (as not found),
// one that is not online and one that does not report proxy.test@1; and a
// second test of the same pool within TestRateWindow.
func (s *Service) RequestTest(ctx context.Context, in TestRequest, actx auditapp.AuditContext) ([]TestHandle, error) {
	if s.test == nil || s.test.cfg.EchoBase == "" {
		return nil, ErrTestUnavailable
	}
	tid, err := parseTenant(in.TenantID)
	if err != nil {
		return nil, err
	}
	pool, err := s.GetPool(ctx, in.TenantID, in.PoolID)
	if err != nil {
		return nil, err
	}
	if len(pool.Endpoints) == 0 {
		return nil, ErrTestNoEndpoint
	}
	ids := dedupe(in.SensorIDs)
	if len(ids) == 0 || len(ids) > TestMaxSensors {
		return nil, ErrTestSensors
	}
	sensors := make([]*sensordom.Sensor, 0, len(ids))
	for _, raw := range ids {
		sid, err := parseRef(raw, pooldom.ErrSensorNotFound)
		if err != nil {
			return nil, err
		}
		sn, err := s.test.sensors.GetByTenantAndID(ctx, tid, sid)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return nil, pooldom.ErrSensorNotFound
			}
			return nil, fmt.Errorf("look up a sensor for the proxy test: %w", err)
		}
		// A shared sensor never connects to an organization's proxy, and the
		// tenant plane answers not found for it, as for another
		// organization's sensor.
		if sn == nil || sn.IsShared() || sn.TenantID == nil || *sn.TenantID != tid {
			return nil, pooldom.ErrSensorNotFound
		}
		switch {
		case !sn.IsAvailable() || (sn.Health != sensordom.SensorHealthOnline && sn.Health != sensordom.SensorHealthLate):
			return nil, ErrTestSensorOffline
		case !slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityProxyTest):
			return nil, ErrTestSensorUnsupported
		}
		sensors = append(sensors, sn)
	}

	s.test.mu.Lock()
	defer s.test.mu.Unlock()
	if err := s.checkTestRate(ctx, tid, pool.ID); err != nil {
		return nil, err
	}
	out := make([]TestHandle, 0, len(sensors))
	for _, sn := range sensors {
		cmd, err := s.queueTest(ctx, tid, pool, sn)
		if err != nil {
			return out, err
		}
		out = append(out, TestHandle{SensorID: sn.ID.String(), SensorName: sn.Name, CommandID: cmd.ID.String()})
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionProxyPoolTestRequested, auditdom.ResourceTypeProxyPool, pool.ID.String()).
			WithResourceName(pool.Name).
			WithMessage(fmt.Sprintf("Proxy pool '%s' tested by sensor '%s'", pool.Name, sn.Name)).
			WithMetadata("sensor_id", sn.ID.String()).
			WithMetadata("command_id", cmd.ID.String()).
			WithMetadata("endpoints", len(pool.Endpoints)).
			WithSeverity(auditdom.SeverityLow))
	}
	return out, nil
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// testPayload is the payload of a proxy_test command (sdk-go
// core.ProxyTestPayload, plus the platform's own members). The command is
// pinned to a sensor that reports proxy.test@1 as of the request; it carries
// no required_capabilities because the poll's capabilities are the
// administrator's declared ones narrowed by the report, which would hide a
// sensor-wide capability from a sensor whose administrator declared tools.
type testPayload struct {
	PoolID               string     `json:"pool_id"`
	Egress               testEgress `json:"egress"`
	Echo                 testEcho   `json:"echo"`
	RequiredCapabilities []string   `json:"required_capabilities"`
}

// testEgress is the pool as a sensor builds it for the test: every endpoint
// of the pool, enabled or not and whatever its health (the test is what
// decides), in priority order, and applying to every target (the echo may
// be on a private address in a self-managed install).
type testEgress struct {
	Mode      string                `json:"mode"`
	PoolID    string                `json:"pool_id"`
	Revision  int                   `json:"revision"`
	Strategy  string                `json:"strategy"`
	AppliesTo string                `json:"applies_to"`
	Endpoints []pooldom.JobEndpoint `json:"endpoints"`
}

type testEcho struct {
	URL     string `json:"url"`
	AltPort int    `json:"alt_port,omitempty"`
	// Nonce is the token in the echo URL; the echo answers a request only
	// with it, while the command is live.
	Nonce string `json:"nonce"`
}

func (s *Service) queueTest(ctx context.Context, tid shared.ID, pool *pooldom.Pool, sn *sensordom.Sensor) (*commanddom.Command, error) {
	cmd, err := commanddom.NewCommand(tid, commanddom.CommandTypeProxyTest, commanddom.CommandPriorityHigh, nil)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("proxy test token: %w", err)
	}
	token := hex.EncodeToString(nonce)
	eg := testEgress{Mode: pooldom.ModePool, PoolID: pool.ID.String(), Revision: pool.Revision,
		Strategy: pooldom.StrategyPriority, AppliesTo: pooldom.AppliesAll, Endpoints: make([]pooldom.JobEndpoint, 0, len(pool.Endpoints))}
	for _, e := range pool.Endpoints {
		eg.Endpoints = append(eg.Endpoints, pooldom.JobEndpoint{ID: e.ID.String(), Scheme: e.Scheme, Host: e.Host, Port: e.Port,
			Weight: 1, Auth: e.HasCredentials()})
	}
	payload, err := json.Marshal(testPayload{
		PoolID: pool.ID.String(),
		Egress: eg,
		Echo: testEcho{URL: s.test.cfg.EchoBase + testEchoPath + TestEchoToken(tid.String(), cmd.ID.String(), token),
			AltPort: s.test.cfg.AltPort, Nonce: token},
	})
	if err != nil {
		return nil, fmt.Errorf("encode proxy_test payload: %w", err)
	}
	cmd.Payload = payload
	cmd.SetSensorID(sn.ID)
	cmd.SetExpiration(s.now().Add(TestCommandTTL))
	if err := s.test.commands.Create(ctx, cmd); err != nil {
		return nil, fmt.Errorf("create proxy_test command: %w", err)
	}
	return cmd, nil
}

// checkTestRate refuses a test while another of the pool was queued within
// TestRateWindow (the most recent proxy_test commands of the tenant are
// read; a pool is one of the few that a tenant tests at a time).
func (s *Service) checkTestRate(ctx context.Context, tid, poolID shared.ID) error {
	typ := commanddom.CommandTypeProxyTest
	page, err := s.test.commands.List(ctx, commanddom.Filter{TenantID: &tid, Type: &typ}, pagination.Pagination{Page: 1, PerPage: 50})
	if err != nil {
		return fmt.Errorf("read the pool's recent tests: %w", err)
	}
	since := s.now().Add(-TestRateWindow)
	for _, c := range page.Data {
		if c.CreatedAt.Before(since) {
			continue
		}
		if id, ok := testPoolOf(c); ok && id == poolID.String() {
			return ErrTestRateLimited
		}
	}
	return nil
}

// testPoolOf is the pool a proxy_test command names.
func testPoolOf(c *commanddom.Command) (string, bool) {
	if c == nil || c.Type != commanddom.CommandTypeProxyTest {
		return "", false
	}
	var p struct {
		PoolID string `json:"pool_id"`
	}
	if err := json.Unmarshal(c.Payload, &p); err != nil || p.PoolID == "" {
		return "", false
	}
	return p.PoolID, true
}

// TestEndpointResult is one endpoint's result, cut to what the platform
// accepts from a sensor.
type TestEndpointResult struct {
	EndpointID     string   `json:"endpoint_id"`
	Address        string   `json:"address"`
	OK             bool     `json:"ok"`
	Class          string   `json:"class,omitempty"`
	HandshakeMs    int      `json:"handshake_ms"`
	ExitIP         string   `json:"exit_ip,omitempty"`
	Families       []string `json:"families,omitempty"`
	PortRestricted *bool    `json:"port_restricted,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// TestOutcome is one sensor's test.
type TestOutcome struct {
	CommandID  string
	SensorID   string
	SensorName string
	// Status is pending, running, completed, failed, canceled or expired.
	Status     string
	Error      string
	FinishedAt *time.Time
	Results    []TestEndpointResult
}

// TestResults reads the tests of one pool by command id. A command of
// another tenant, of another pool or of another type is not found, like one
// that does not exist.
func (s *Service) TestResults(ctx context.Context, tenantID, poolID string, commandIDs []string) ([]TestOutcome, error) {
	if s.test == nil {
		return nil, ErrTestUnavailable
	}
	tid, err := parseTenant(tenantID)
	if err != nil {
		return nil, err
	}
	pool, err := s.GetPool(ctx, tenantID, poolID)
	if err != nil {
		return nil, err
	}
	ids := dedupe(commandIDs)
	if len(ids) == 0 || len(ids) > TestMaxSensors {
		return nil, ErrTestSensors
	}
	byID := make(map[string]*pooldom.Endpoint, len(pool.Endpoints))
	for _, e := range pool.Endpoints {
		byID[e.ID.String()] = e
	}
	out := make([]TestOutcome, 0, len(ids))
	for _, raw := range ids {
		cid, err := parseRef(raw, pooldom.ErrPoolNotFound)
		if err != nil {
			return nil, err
		}
		c, err := s.test.commands.GetByTenantAndID(ctx, tid, cid)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return nil, pooldom.ErrPoolNotFound
			}
			return nil, err
		}
		if p, ok := testPoolOf(c); !ok || p != pool.ID.String() {
			return nil, pooldom.ErrPoolNotFound
		}
		o := TestOutcome{CommandID: c.ID.String(), Status: testStatus(c.Status), FinishedAt: c.CompletedAt}
		if c.SensorID != nil {
			o.SensorID = c.SensorID.String()
			if sn, err := s.test.sensors.GetByTenantAndID(ctx, tid, *c.SensorID); err == nil && sn != nil {
				o.SensorName = sn.Name
			}
		}
		switch c.Status {
		case commanddom.CommandStatusCompleted:
			o.Results = testResultsOf(c, byID)
		case commanddom.CommandStatusFailed:
			o.Error = pooldom.SanitizeError(c.ErrorMessage)
		}
		out = append(out, o)
	}
	return out, nil
}

func testStatus(st commanddom.CommandStatus) string {
	switch st {
	case commanddom.CommandStatusAcknowledged, commanddom.CommandStatusRunning:
		return "running"
	case commanddom.CommandStatusCompleted:
		return "completed"
	case commanddom.CommandStatusFailed:
		return "failed"
	case commanddom.CommandStatusCanceled:
		return "canceled"
	case commanddom.CommandStatusExpired:
		return "expired"
	default:
		return "pending"
	}
}

// Classes a result may carry (sdk-go upstream.EndpointResult.Class).
var testClasses = []string{"proxy_down", "proxy_auth", "target_unreachable", "target_refused", "echo_failed"}

// testResultsOf reads the sensor's result of a finished test. The sensor is
// not trusted: only endpoints of the pool, a closed set of classes and
// families, a parsed exit address, a bounded time and sanitized text pass.
func testResultsOf(c *commanddom.Command, endpoints map[string]*pooldom.Endpoint) []TestEndpointResult {
	var res struct {
		Metadata struct {
			ProxyTest struct {
				PoolID    string `json:"pool_id"`
				Endpoints []struct {
					EndpointID     string   `json:"endpoint_id"`
					OK             bool     `json:"ok"`
					Class          string   `json:"class"`
					HandshakeMs    int      `json:"handshake_ms"`
					ExitIP         string   `json:"exit_ip"`
					Families       []string `json:"families"`
					PortRestricted *bool    `json:"port_restricted"`
					Error          string   `json:"error"`
				} `json:"endpoints"`
			} `json:"proxy_test"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(c.Result, &res); err != nil {
		return []TestEndpointResult{}
	}
	out := make([]TestEndpointResult, 0, len(res.Metadata.ProxyTest.Endpoints))
	seen := map[string]bool{}
	for _, r := range res.Metadata.ProxyTest.Endpoints {
		e, ok := endpoints[r.EndpointID]
		if !ok || seen[r.EndpointID] {
			continue
		}
		seen[r.EndpointID] = true
		o := TestEndpointResult{EndpointID: r.EndpointID, Address: e.Address(),
			HandshakeMs: min(max(r.HandshakeMs, 0), 600_000), Error: pooldom.SanitizeError(r.Error)}
		if slices.Contains(testClasses, r.Class) {
			o.Class = r.Class
		}
		o.OK = r.OK && o.Class == ""
		if !o.OK && o.Class == "" {
			o.Class = "proxy_down"
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(r.ExitIP)); err == nil && a.Zone() == "" {
			o.ExitIP = a.Unmap().String()
		}
		for _, f := range []string{"v4", "v6"} {
			if slices.Contains(r.Families, f) {
				o.Families = append(o.Families, f)
			}
		}
		if o.OK {
			o.PortRestricted = r.PortRestricted
		}
		out = append(out, o)
	}
	return out
}

// OnProxyTestFinished records a finished test (completed or failed) in the
// audit log: the sensor, how many endpoints passed and the failure classes.
// Never an address, an exit address or a credential.
func (s *Service) OnProxyTestFinished(ctx context.Context, c *commanddom.Command) {
	poolID, ok := testPoolOf(c)
	if !ok {
		return
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionProxyPoolTested, auditdom.ResourceTypeProxyPool, poolID).
		WithSeverity(auditdom.SeverityLow)
	if c.SensorID != nil {
		ev = ev.WithMetadata("sensor_id", c.SensorID.String())
	}
	ev = ev.WithMetadata("command_id", c.ID.String())
	if c.Status == commanddom.CommandStatusFailed {
		s.logAudit(ctx, auditapp.AuditContext{TenantID: c.TenantID.String()},
			ev.WithMessage("Proxy test failed: "+pooldom.SanitizeError(c.ErrorMessage)).WithMetadata("outcome", "failed"))
		return
	}
	// Endpoint ids are not needed to count: accept every id here.
	all := map[string]*pooldom.Endpoint{}
	var raw struct {
		Metadata struct {
			ProxyTest struct {
				Endpoints []struct {
					EndpointID string `json:"endpoint_id"`
				} `json:"endpoints"`
			} `json:"proxy_test"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(c.Result, &raw)
	for _, e := range raw.Metadata.ProxyTest.Endpoints {
		if id, err := shared.IDFromString(e.EndpointID); err == nil {
			all[e.EndpointID] = &pooldom.Endpoint{ID: id}
		}
	}
	// Exit addresses are kept only where the platform's echo saw them.
	kept, dropped := s.recordVerifiedExits(ctx, c)
	passed, classes := 0, map[string]int{}
	results := testResultsOf(c, all)
	for _, r := range results {
		if r.OK {
			passed++
		} else {
			classes[r.Class]++
		}
	}
	s.logAudit(ctx, auditapp.AuditContext{TenantID: c.TenantID.String()},
		ev.WithMessage(fmt.Sprintf("Proxy test finished: %d of %d endpoints passed", passed, len(results))).
			WithMetadata("outcome", "completed").
			WithMetadata("passed", passed).
			WithMetadata("tested", len(results)).
			WithMetadata("failure_classes", classes).
			WithMetadata("exits_verified", kept).
			WithMetadata("exits_unverified", dropped))
}

// TestEchoToken is the one path segment of a test's echo URL: the tenant, the
// command and the nonce, joined by dots. Only the nonce is secret; the other
// two let the echo find the command without a tenant in the URL path.
func TestEchoToken(tenantID, commandID, nonce string) string {
	return tenantID + "." + commandID + "." + nonce
}

// SplitTestEchoToken is the inverse of TestEchoToken.
func SplitTestEchoToken(token string) (tenantID, commandID, nonce string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// VerifyTestEcho reports whether a request to the platform's echo carries
// the token of a live proxy_test command of that tenant: the command exists,
// is a proxy_test, has been taken by a sensor and has not ended, and the
// nonce is the one in its payload. Anything else is false and the echo
// answers not found, so the page tells nothing to a caller without a token.
func (s *Service) VerifyTestEcho(ctx context.Context, tenantID, commandID, nonce string) bool {
	if s.test == nil || len(nonce) != 32 {
		return false
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false
	}
	cid, err := shared.IDFromString(commandID)
	if err != nil {
		return false
	}
	c, err := s.test.commands.GetByTenantAndID(ctx, tid, cid)
	if err != nil || c == nil || c.Type != commanddom.CommandTypeProxyTest {
		return false
	}
	if c.Status != commanddom.CommandStatusAcknowledged && c.Status != commanddom.CommandStatusRunning {
		return false
	}
	var p struct {
		Echo struct {
			Nonce string `json:"nonce"`
		} `json:"echo"`
	}
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(p.Echo.Nonce), []byte(nonce)) == 1
}

// TestCredentialsFor returns the credentials of the pool a proxy_test
// command names, for the sensor holding its live lease (the caller checked
// that). The pool must be the command's: anything else is ErrPoolNotFound.
// All endpoints' credentials are returned, enabled or not: the test is what
// decides.
func (s *Service) TestCredentialsFor(ctx context.Context, c *commanddom.Command, poolID string) ([]Credential, error) {
	p, err := s.testPoolFor(ctx, c, poolID)
	if err != nil {
		return nil, err
	}
	out := []Credential{}
	for _, e := range p.Endpoints {
		if !e.HasCredentials() {
			continue
		}
		cr, err := s.openCredentials(e)
		if err != nil {
			s.logger.Error("proxy credentials do not open", "tenant_id", c.TenantID.String(), "endpoint_id", e.ID.String())
			continue
		}
		out = append(out, Credential{EndpointID: e.ID.String(), Username: cr.Username, Password: cr.Password})
	}
	return out, nil
}

// ApplyTestReport folds the egress report of a proxy_test command into the
// health of the pool it names, like ApplyReport does for the pool a
// sensor's jobs use.
func (s *Service) ApplyTestReport(ctx context.Context, c *commanddom.Command, sensorID shared.ID, r Report) error {
	p, err := s.testPoolFor(ctx, c, r.PoolID)
	if err != nil {
		return err
	}
	return s.applyHealth(ctx, p, sensorID, r)
}

// testPoolFor is the pool of a proxy_test command when poolID is it.
func (s *Service) testPoolFor(ctx context.Context, c *commanddom.Command, poolID string) (*pooldom.Pool, error) {
	named, ok := testPoolOf(c)
	if !ok || named != poolID {
		return nil, pooldom.ErrPoolNotFound
	}
	pid, err := parseRef(poolID, pooldom.ErrPoolNotFound)
	if err != nil {
		return nil, err
	}
	return s.repo.GetPool(ctx, c.TenantID, pid)
}

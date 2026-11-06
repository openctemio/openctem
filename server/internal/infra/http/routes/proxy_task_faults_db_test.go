package routes

// Task-reported proxy faults (docs/architecture/sensor-proxies.md): the
// platform records the pool and endpoints it hands a pooled job and charges
// the job's own proxy verdict (proxy_unavailable gaps or outcomes, a pool
// exhaustion failure) to exactly those endpoints, so a dead proxy is
// quarantined even when no egress report arrives. Over the real v2 routes
// and a migrated database. Requires DATABASE_URL.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	proxypoolapp "github.com/openctemio/openctem/api/internal/app/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
)

func proxyGapResult(host, otherEndpoint string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"coverage_gaps": []map[string]any{{"host": host, "reason": "proxy_unavailable",
				"detail": "the proxy pool could not carry a connection to port 443 (proxy_down)"}},
			"coverage_gaps_total": 1,
		},
		// A sensor-named endpoint the platform did not hand the job.
		"egress": map[string]any{"endpoint_id": otherEndpoint, "proxy_down": 50},
	}
}

func targetSideResult() map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"coverage_gaps": []map[string]any{
				{"host": "a.example.com", "reason": "blocked"},
				{"host": "b.example.com", "reason": "breaker_open"},
			},
			"coverage_gaps_total": 2,
		},
		// The job's one target ("."), failed by the target (no follow-up).
		"target_outcomes": []map[string]any{
			{"target": ".", "state": "failed", "class": "timeout", "cause": "target"},
		},
	}
}

// runJob gives sensor s one scan job and ends it with body on action
// ("complete" or "fail"); it returns the command id.
func (h *ctlHarness) runJob(s ctlSensor, tenantID, action string, body any) string {
	h.t.Helper()
	id := h.newCommand(tenantID, s.id)
	got := h.pollClaim(s)
	if len(got) != 1 || got[0].ID != id {
		h.t.Fatalf("poll = %+v", got)
	}
	base := "/api/v2/sensor/commands/" + id
	if action == "complete" {
		resp, raw := h.call(s.key, http.MethodPost, base+"/start", nil)
		h.want(resp, raw, 200, "")
	}
	resp, raw := h.call(s.key, http.MethodPost, base+"/"+action, body)
	h.want(resp, raw, 200, "")
	return id
}

func (h *ctlHarness) endpointState(id string) (string, float64) {
	h.t.Helper()
	var (
		state string
		score float64
	)
	if err := h.db.QueryRow(`SELECT state, score FROM proxy_endpoints WHERE id = $1`, id).Scan(&state, &score); err != nil {
		h.t.Fatal(err)
	}
	return state, score
}

func TestProxyTaskFaults_QuarantineAssignedEndpointOnly(t *testing.T) {
	h := newCtlHarnessWith(t, true)
	ctx := context.Background()
	s := h.newSensor(h.tenantID, "proxy-task")
	h.reportCaps(s, "net.confined@1", "egress.upstream@1")
	pool := h.newPool(h.tenantID, "segment", "socks5://10.9.0.1:1080\nsocks5://10.9.0.2:1080", false)
	if err := h.egress.AssignSensor(ctx, h.tenantID, s.id, proxypool.ModePool, pool.ID.String(), auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	dead, spare := pool.Endpoints[0].ID.String(), pool.Endpoints[1].ID.String()
	// The spare is disabled: never handed to a job.
	off := false
	if _, err := h.egress.UpdateEndpoint(ctx, proxypoolapp.UpdateEndpointInput{TenantID: h.tenantID, PoolID: pool.ID.String(),
		EndpointID: spare, Enabled: &off}, auditapp.AuditContext{TenantID: h.tenantID}); err != nil {
		t.Fatal(err)
	}
	spareBefore, _ := h.endpointState(spare)

	// Target-side failures never lower proxy health.
	for i := 0; i < 6; i++ {
		h.runJob(s, h.tenantID, "complete", map[string]any{"result": targetSideResult()})
	}
	if st, score := h.endpointState(dead); st == proxypool.StateQuarantined || score < 0.5 {
		t.Fatalf("target-side failures moved the proxy: %s %.2f", st, score)
	}

	// The job records the path it was handed: the pool and the enabled endpoint.
	first := h.runJob(s, h.tenantID, "complete", map[string]any{"result": proxyGapResult("h0.example.com", spare)})
	var (
		recPool, verdict string
		eps              []string
	)
	if err := h.db.QueryRow(`SELECT pool_id, endpoint_ids::text[], verdict FROM proxy_command_egress WHERE command_id = $1`, first).
		Scan(&recPool, pq.Array(&eps), &verdict); err != nil {
		t.Fatal(err)
	}
	if recPool != pool.ID.String() || len(eps) != 1 || eps[0] != dead || verdict != proxypool.VerdictProxyFault {
		t.Fatalf("record = %s %v %s", recPool, eps, verdict)
	}
	// The 6 clean jobs keep the ratio rule below half: four more faulted
	// jobs stay under the limit of five, the fifth quarantines.
	for i := 1; i < 4; i++ {
		h.runJob(s, h.tenantID, "complete", map[string]any{"result": proxyGapResult("h.example.com", spare)})
	}
	if st, _ := h.endpointState(dead); st == proxypool.StateQuarantined {
		t.Fatal("quarantined below the threshold")
	}
	// A pool-exhaustion failure is the fifth faulted job.
	h.runJob(s, h.tenantID, "fail", map[string]any{"error_message": "no proxy endpoint carried a connection",
		"failure": map[string]any{"class": proxypool.ClassPoolExhausted}})
	if st, _ := h.endpointState(dead); st != proxypool.StateQuarantined {
		t.Fatalf("dead endpoint: %s, want quarantined", st)
	}
	// The sensor-named endpoint the job was never handed is untouched.
	if st, _ := h.endpointState(spare); st != spareBefore {
		t.Fatalf("unassigned endpoint moved: %s -> %s", spareBefore, st)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM proxy_command_egress WHERE pool_id = $1 AND verdict = 'ok'`, pool.ID.String()).Scan(&n); err != nil || n != 6 {
		t.Fatalf("clean verdicts = %d (%v)", n, err)
	}
}

// SECURITY (tenant isolation): another tenant's jobs never touch this
// tenant's pool, also when a record names it directly.
func TestProxyTaskFaults_OtherTenantNeverMovesThePool(t *testing.T) {
	h := newCtlHarnessWith(t, true)
	ctx := context.Background()
	sA := h.newSensor(h.tenantID, "proxy-a")
	h.reportCaps(sA, "net.confined@1", "egress.upstream@1")
	poolA := h.newPool(h.tenantID, "a", "socks5://10.9.0.1:1080", false)
	if err := h.egress.AssignSensor(ctx, h.tenantID, sA.id, proxypool.ModePool, poolA.ID.String(), auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	epA := poolA.Endpoints[0].ID.String()
	stateA, scoreA := h.endpointState(epA)

	tenantB := h.newTenant()
	sB := h.newSensor(tenantB, "proxy-b")
	h.reportCaps(sB, "net.confined@1", "egress.upstream@1")
	poolB := h.newPool(tenantB, "b", "socks5://10.9.0.1:1080", false)
	if err := h.egress.AssignSensor(ctx, tenantB, sB.id, proxypool.ModePool, poolB.ID.String(), auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		h.runJob(sB, tenantB, "complete", map[string]any{"result": proxyGapResult("h.example.com", epA)})
	}
	if st, _ := h.endpointState(poolB.Endpoints[0].ID.String()); st != proxypool.StateQuarantined {
		t.Fatalf("tenant B's own endpoint: %s, want quarantined", st)
	}
	if st, score := h.endpointState(epA); st != stateA || score != scoreA {
		t.Fatalf("tenant B's jobs moved tenant A's endpoint: %s %.2f", st, score)
	}

	// A record of tenant B's job that names tenant A's pool is refused by
	// the store, so its verdict charges nothing.
	cmdB := h.newCommand(tenantB, sB.id)
	if _, err := h.db.Exec(`UPDATE commands SET status = 'running', sensor_id = $2 WHERE id = $1`, cmdB, sB.id); err != nil {
		t.Fatal(err)
	}
	eg := proxypool.BuildJobEgress(poolA, proxypool.AppliesAll, time.Now())
	if err := h.egress.RecordJobEgress(ctx, mustID(t, tenantB), mustID(t, cmdB), mustID(t, sB.id), 0, &eg); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM proxy_command_egress WHERE command_id = $1`, cmdB).Scan(&n); err != nil || n != 0 {
		t.Fatalf("cross-tenant record stored: %d (%v)", n, err)
	}
	for i := 0; i < 5; i++ {
		if err := h.egress.ObserveJobVerdict(ctx, mustID(t, tenantB), mustID(t, cmdB), mustID(t, sB.id), 0,
			proxypool.TaskVerdict{Verdict: proxypool.VerdictProxyFault, Faults: 3}); err != nil {
			t.Fatal(err)
		}
	}
	if st, score := h.endpointState(epA); st != stateA || score != scoreA {
		t.Fatalf("cross-tenant verdict moved tenant A's endpoint: %s %.2f", st, score)
	}
}

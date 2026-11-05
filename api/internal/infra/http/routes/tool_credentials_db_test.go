package routes

// Tool source keys, sensor side (docs/architecture/tool-source-keys.md), over
// the real v2 route and a migrated database: an organization's keys reach
// only the sensor holding a live task of that organization's job, for the
// job's tool; never another tenant's sensor, never another tenant's keys,
// and a shared sensor gets the keys of the held job's organization only.
// Requires DATABASE_URL.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	toolsourceapp "github.com/openctemio/openctem/api/internal/app/toolsource"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

const (
	keyOfA = "tenant-a-securitytrails-key-0001"
	keyOfB = "tenant-b-securitytrails-key-0002"
)

type toolKeyHarness struct {
	*ctlHarness
	keys *toolsourceapp.Service
}

func newToolKeyHarness(t *testing.T) *toolKeyHarness {
	t.Helper()
	var keys *toolsourceapp.Service
	h := newCtlHarnessConfig(t, ctlHarnessConfig{toolKeys: func(db *postgres.DB) (handler.ToolKeySource, handler.SensorGrantReader) {
		enc, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		keys = toolsourceapp.NewService(postgres.NewToolSourceKeyRepository(db), enc, nil, logger.NewNop())
		return keys, postgres.NewSensorGrantRepository(db)
	}})
	return &toolKeyHarness{ctlHarness: h, keys: keys}
}

func (h *toolKeyHarness) setKey(tenantID, source, value string) {
	h.t.Helper()
	if _, err := h.keys.StoreKey(context.Background(), tenantID, source, value, auditapp.AuditContext{TenantID: tenantID}); err != nil {
		h.t.Fatalf("set key: %v", err)
	}
}

func (h *toolKeyHarness) trust(s ctlSensor) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensors SET trust_level = 'trusted' WHERE id = $1`, s.id); err != nil {
		h.t.Fatal(err)
	}
}

// runningJob creates a scan command of tenantID with payload, running for
// sensor holder under lease epoch 3.
func (h *toolKeyHarness) runningJob(tenantID, holder, payload string, shared bool) string {
	h.t.Helper()
	id := h.newCommand(tenantID, "")
	if _, err := h.db.ExecContext(context.Background(), `
		UPDATE commands SET payload = $2::jsonb, is_platform_job = $4, status = 'running', sensor_id = $3, lease_epoch = 3,
		       acknowledged_at = now(), started_at = now(), lease_expires_at = now() + interval '10 minutes'
		WHERE id = $1`, id, payload, holder, shared); err != nil {
		h.t.Fatalf("running job: %v", err)
	}
	return id
}

func (h *toolKeyHarness) fetch(key, commandID, tool, epoch string) (*http.Response, protov2.ToolCredentialsResponse) {
	h.t.Helper()
	hdr := []string{}
	if epoch != "" {
		hdr = append(hdr, protov2.HeaderLeaseEpoch, epoch)
	}
	resp, raw := h.call(key, http.MethodPost, "/api/v2/sensor/commands/"+commandID+"/"+protov2.ToolCredentialsAction,
		map[string]any{"tool": tool}, hdr...)
	var out protov2.ToolCredentialsResponse
	if resp.StatusCode == http.StatusOK {
		out = decodeAs[protov2.ToolCredentialsResponse](h.t, raw)
	} else if !strings.Contains(string(raw), "command-not-found") && !strings.Contains(string(raw), "invalid") {
		h.t.Fatalf("refusal body: %d %s", resp.StatusCode, raw)
	}
	return resp, out
}

const subfinderJob = `{"scanner":"subfinder","targets":["example.com"]}`

func credValues(r protov2.ToolCredentialsResponse) map[string]string {
	out := map[string]string{}
	for _, c := range r.Credentials {
		out[c.Name] = c.Value
	}
	return out
}

func TestToolCredentials_OrganizationKeysOnlyForItsOwnLeasedTask(t *testing.T) {
	h := newToolKeyHarness(t)
	tenantA, tenantB := h.tenantID, h.newTenant()
	h.setKey(tenantA, "securitytrails", keyOfA)
	h.setKey(tenantA, "shodan", "tenant-a-shodan-key-0000003")
	h.setKey(tenantB, "securitytrails", keyOfB)

	sA := h.newSensor(tenantA, "keys-a")
	h.trust(sA)
	sA2 := h.newSensor(tenantA, "keys-a2")
	h.trust(sA2)
	sB := h.newSensor(tenantB, "keys-b")
	h.trust(sB)

	jobA := h.runningJob(tenantA, sA.id, subfinderJob, false)
	resp, out := h.fetch(sA.key, jobA, "subfinder", "3")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lease holder refused: %d", resp.StatusCode)
	}
	got := credValues(out)
	if got["securitytrails"] != keyOfA || got["shodan"] == "" || len(got) != 2 || !out.LocalFallback {
		t.Fatalf("tenant A's task got %v (local_fallback %v)", got, out.LocalFallback)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("keys answer is cacheable")
	}
	// Tenant B's own task gets B's key and never A's.
	jobB := h.runningJob(tenantB, sB.id, subfinderJob, false)
	if _, out := h.fetch(sB.key, jobB, "subfinder", "3"); credValues(out)["securitytrails"] != keyOfB || len(out.Credentials) != 1 {
		t.Fatalf("tenant B's task got %v", credValues(out))
	}

	// Every refusal is the same command-not-found.
	for name, c := range map[string]struct{ key, cmd, tool, epoch string }{
		"tenant B's sensor on A's job":     {sB.key, jobA, "subfinder", "3"},
		"another sensor of A, not holding": {sA2.key, jobA, "subfinder", "3"},
		"wrong lease epoch":                {sA.key, jobA, "subfinder", "4"},
		"no lease epoch":                   {sA.key, jobA, "subfinder", ""},
		"another tool than the job's":      {sA.key, jobA, "nuclei", "3"},
		"a tool without keys":              {sA.key, h.runningJob(tenantA, sA.id, `{"scanner":"semgrep","target":"."}`, false), "semgrep", "3"},
	} {
		resp, out := h.fetch(c.key, c.cmd, c.tool, c.epoch)
		if resp.StatusCode != http.StatusNotFound || len(out.Credentials) != 0 {
			t.Errorf("%s: %d %v", name, resp.StatusCode, credValues(out))
		}
	}

	// No replay after the lease ends: a completed or failed job, asked by
	// the same sensor under the same lease epoch, gets nothing.
	for _, end := range []string{"completed", "failed"} {
		job := h.runningJob(tenantA, sA.id, subfinderJob, false)
		if resp, _ := h.fetch(sA.key, job, "subfinder", "3"); resp.StatusCode != http.StatusOK {
			t.Fatalf("running job before %s: %d", end, resp.StatusCode)
		}
		if _, err := h.db.ExecContext(context.Background(), `UPDATE commands SET status = $2, completed_at = now() WHERE id = $1`, job, end); err != nil {
			t.Fatal(err)
		}
		if resp, out := h.fetch(sA.key, job, "subfinder", "3"); resp.StatusCode != http.StatusNotFound || len(out.Credentials) != 0 {
			t.Fatalf("%s job, same sensor and epoch: %d %v", end, resp.StatusCode, credValues(out))
		}
	}

	// A disabled key is not delivered.
	if _, err := h.keys.SwitchKey(context.Background(), tenantA, "shodan", false, auditapp.AuditContext{TenantID: tenantA}); err != nil {
		t.Fatal(err)
	}
	jobA2 := h.runningJob(tenantA, sA.id, subfinderJob, false)
	if _, out := h.fetch(sA.key, jobA2, "subfinder", "3"); len(out.Credentials) != 1 || credValues(out)["securitytrails"] != keyOfA {
		t.Fatalf("disabled key delivered: %v", credValues(out))
	}
	var used int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM tool_source_keys WHERE tenant_id = $1 AND last_used_at IS NOT NULL`, tenantA).Scan(&used); err != nil || used == 0 {
		t.Fatalf("delivery not recorded: %d %v", used, err)
	}
}

func TestToolCredentials_UntrustedSensorGetsNone(t *testing.T) {
	h := newToolKeyHarness(t)
	h.setKey(h.tenantID, "securitytrails", keyOfA)
	s := h.newSensor(h.tenantID, "keys-new")
	job := h.runningJob(h.tenantID, s.id, subfinderJob, false)
	resp, out := h.fetch(s.key, job, "subfinder", "3")
	if resp.StatusCode != http.StatusOK || len(out.Credentials) != 0 || !out.LocalFallback {
		t.Fatalf("untrusted sensor: %d %v fallback %v", resp.StatusCode, credValues(out), out.LocalFallback)
	}
}

func TestToolCredentials_SharedSensorGetsTheHeldJobsOrganizationOnly(t *testing.T) {
	h := newToolKeyHarness(t)
	tenantA, tenantB := h.tenantID, h.newTenant()
	h.setKey(tenantA, "securitytrails", keyOfA)
	h.setKey(tenantB, "securitytrails", keyOfB)
	shared := h.newSharedSensor("keys-shared")

	jobA := h.runningJob(tenantA, shared.id, subfinderJob, true)
	jobB := h.runningJob(tenantB, shared.id, subfinderJob, true)
	for _, c := range []struct{ job, want string }{{jobA, keyOfA}, {jobB, keyOfB}} {
		resp, out := h.fetch(shared.key, c.job, "subfinder", "3")
		got := credValues(out)
		if resp.StatusCode != http.StatusOK || len(got) != 1 || got["securitytrails"] != c.want || out.LocalFallback {
			t.Fatalf("shared sensor on %s: %d %v fallback %v", c.job, resp.StatusCode, got, out.LocalFallback)
		}
	}
	// A job of A that the shared sensor does not hold (an organization job)
	// gives nothing.
	sA := h.newSensor(tenantA, "keys-a")
	orgJob := h.runningJob(tenantA, sA.id, subfinderJob, false)
	if resp, _ := h.fetch(shared.key, orgJob, "subfinder", "3"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("shared sensor read an organization job: %d", resp.StatusCode)
	}
}

// A job that names only the capability gets the keys of the tool that
// implements it, and no other tool's.
func TestToolCredentials_CapabilityJob(t *testing.T) {
	h := newToolKeyHarness(t)
	h.setKey(h.tenantID, "securitytrails", keyOfA)
	s := h.newSensor(h.tenantID, "keys-cap")
	h.trust(s)
	job := h.runningJob(h.tenantID, s.id, `{"capability":"discover.subdomains@1","targets":["example.com"]}`, false)
	if _, out := h.fetch(s.key, job, "subfinder", "3"); credValues(out)["securitytrails"] != keyOfA {
		t.Fatalf("capability job: %v", credValues(out))
	}
	if resp, _ := h.fetch(s.key, job, "nuclei", "3"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("capability job, other tool: %d", resp.StatusCode)
	}
}

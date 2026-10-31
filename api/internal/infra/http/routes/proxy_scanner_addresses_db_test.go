package routes

// Scanner addresses (docs/architecture/sensor-proxies.md, "Scanner
// addresses") over the real routes and a migrated database: a proxy's exit
// address is kept only when the platform's echo saw it for the same test
// (a sensor's claim alone never adds one), the list is the caller's
// organization only, shared sensors are never listed as the tenant's, and
// no response carries a credential. Requires DATABASE_URL.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	proxypoolapp "github.com/openctemio/openctem/api/internal/app/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type ppScannerAddresses struct {
	Items []struct {
		Address    string `json:"address"`
		CIDR       string `json:"cidr"`
		Kind       string `json:"kind"`
		Private    bool   `json:"private"`
		PoolName   string `json:"pool_name"`
		EndpointID string `json:"endpoint_id"`
		SensorID   string `json:"sensor_id"`
	} `json:"items"`
	CIDRs []string `json:"cidrs"`
}

func (h *ppHarness) scannerAddresses(c ppCaller) ppScannerAddresses {
	h.t.Helper()
	status, body := h.do(c, http.MethodGet, "/api/v1/proxy-pools/scanner-addresses", nil)
	if status != http.StatusOK {
		h.t.Fatalf("scanner addresses = %d %s", status, body)
	}
	h.noSecret("scanner addresses", body)
	if strings.Contains(body, "10.0.0.5") || strings.Contains(body, "1080") {
		h.t.Fatalf("an endpoint's own address in the scanner addresses: %s", body)
	}
	var out ppScannerAddresses
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// recordedExits lists every stored exit of both tenants as endpoint=address.
func (h *ppHarness) recordedExits() []string {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT endpoint_id::text, host(address) FROM proxy_endpoint_exits WHERE tenant_id = ANY($1::uuid[])`,
		"{"+h.tenantA.String()+","+h.tenantB.String()+"}")
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var ep, a string
		if err := rows.Scan(&ep, &a); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, ep+"="+a)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (v ppScannerAddresses) kinds() map[string]string {
	out := map[string]string{}
	for _, it := range v.Items {
		out[it.Address] = it.Kind
	}
	return out
}

func TestProxyScannerAddresses_OnlyEchoVerifiedExitsPerTenant(t *testing.T) {
	h := newPPHarness(t)
	ctx := context.Background()
	admin := ppCaller{Tenant: h.tenantA}
	adminB := ppCaller{Tenant: h.tenantB}
	h.exec(`UPDATE sensors SET health = 'online', reported_capabilities = ARRAY['proxy.test@1'] WHERE id = $1`, h.sensorA.String())

	status, body := h.do(admin, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "egress",
		"endpoints_text": "socks5://pp-user:" + ppSecret + "@10.0.0.5:1080#dc1\nhttp://10.0.0.6:3128"})
	if status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	pool := decodePool(t, body)
	_, bBody := h.do(adminB, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "b", "endpoints_text": "http://10.1.0.5:3128"})
	poolB := decodePool(t, bBody)

	status, body = h.do(admin, http.MethodPost, "/api/v1/proxy-pools/"+pool.ID+"/test", map[string]any{"sensor_ids": []string{h.sensorA.String()}})
	if status != http.StatusAccepted {
		t.Fatalf("test = %d %s", status, body)
	}
	var started struct {
		Items []struct {
			CommandID string `json:"command_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &started); err != nil || len(started.Items) != 1 {
		t.Fatalf("test response %s (%v)", body, err)
	}
	cmdID := started.Items[0].CommandID
	var nonce string
	if err := h.db.QueryRow(`SELECT payload->'echo'->>'nonce' FROM commands WHERE id = $1`, cmdID).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	echo := func(tenant shared.ID, token string) int {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			h.srv.URL+"/api/v1/proxy-test-echoes/"+proxypoolapp.TestEchoToken(tenant.String(), cmdID, token), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	observations := func() int {
		var n int
		if err := h.db.QueryRow(`SELECT COUNT(*) FROM proxy_echo_observations WHERE command_id = $1`, cmdID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// A pending test, a wrong token and another tenant record nothing.
	echo(h.tenantA, nonce)
	h.exec(`UPDATE commands SET status = 'running' WHERE id = $1`, cmdID)
	echo(h.tenantA, strings.Repeat("b", 32))
	echo(h.tenantB, nonce)
	if n := observations(); n != 0 {
		t.Fatalf("observations before a valid echo = %d", n)
	}
	if status := echo(h.tenantA, nonce); status != http.StatusOK {
		t.Fatalf("echo = %d", status)
	}
	if n := observations(); n != 1 {
		t.Fatalf("observations after the echo = %d", n)
	}
	// Another tenant cannot add an observation to our command.
	if err := h.repo.RecordEchoObservation(ctx, h.tenantB, shared.MustIDFromString(cmdID), netip.MustParseAddr("198.51.100.66"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := observations(); n != 1 {
		t.Fatalf("tenant B added an observation: %d", n)
	}

	// The sensor completes claiming three exits: one the echo saw (kept),
	// one it never saw (dropped) and one for tenant B's endpoint (dropped).
	e0, e1 := pool.Endpoints[0].ID, pool.Endpoints[1].ID
	result, _ := json.Marshal(map[string]any{"metadata": map[string]any{"proxy_test": map[string]any{
		"pool_id": pool.ID, "endpoints": []map[string]any{
			{"endpoint_id": e0, "ok": true, "exit_ip": "127.0.0.1"},
			{"endpoint_id": e1, "ok": true, "exit_ip": "198.51.100.7"},
			{"endpoint_id": poolB.Endpoints[0].ID, "ok": true, "exit_ip": "127.0.0.1"},
		}}}})
	h.exec(`UPDATE commands SET status = 'completed', completed_at = now(), result = $2 WHERE id = $1`, cmdID, string(result))
	cmd, err := h.cmds.GetByTenantAndID(ctx, h.tenantA, shared.MustIDFromString(cmdID))
	if err != nil {
		t.Fatal(err)
	}
	h.svc.OnProxyTestFinished(ctx, cmd)
	exits := h.recordedExits()
	if len(exits) != 1 || exits[0] != e0+"=127.0.0.1" {
		t.Fatalf("recorded exits %v, want only %s=127.0.0.1", exits, e0)
	}
	if n := observations(); n != 0 {
		t.Fatalf("observations left after the test = %d", n)
	}
	// Tenant B cannot attach an exit to our pool's endpoint.
	if err := h.repo.RecordEndpointExits(ctx, h.tenantB, shared.MustIDFromString(pool.ID), shared.NewID(),
		[]proxypool.EndpointExit{{EndpointID: shared.MustIDFromString(e1), Address: netip.MustParseAddr("198.51.100.8")}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM proxy_endpoint_exits WHERE host(address) = '198.51.100.8'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("cross-tenant exit stored: %d %v", n, err)
	}

	// Sensors' observed addresses: ours, tenant B's, the shared sensor's and
	// one not seen for 40 days.
	h.exec(`UPDATE sensors SET ip_address = '203.0.113.20', api_key_last_used_ip = '203.0.113.21', last_seen_at = now() WHERE id = $1`, h.sensorA.String())
	h.exec(`UPDATE sensors SET ip_address = '203.0.113.30', last_seen_at = now() WHERE id = $1`, h.sensorB.String())
	h.exec(`UPDATE sensors SET ip_address = '203.0.113.40', last_seen_at = now() WHERE id = $1`, h.sharedSensor.String())
	stale := shared.NewID()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, scope, ip_address, last_seen_at)
		VALUES ($1, $2, 'pp-stale', 'worker', 'active', 'unknown', 'daemon', $3, 'octs_pp', 'organization', '203.0.113.50', now() - interval '40 days')`,
		stale.String(), h.tenantA.String(), "pp-hash-"+stale.String())

	got := h.scannerAddresses(admin)
	k := got.kinds()
	want := map[string]string{"127.0.0.1": "proxy_exit", "203.0.113.20": "sensor", "203.0.113.21": "sensor", "192.0.2.0/24": "platform"}
	for a, kind := range want {
		if k[a] != kind {
			t.Errorf("address %s = %q, want %q (%+v)", a, k[a], kind, got.Items)
		}
	}
	for _, a := range []string{"198.51.100.7", "203.0.113.30", "203.0.113.40", "203.0.113.50", "not-an-address"} {
		if _, ok := k[a]; ok {
			t.Errorf("address %s listed for tenant A", a)
		}
	}
	if strings.Join(got.CIDRs, ",") != "127.0.0.1/32,192.0.2.0/24,203.0.113.20/32,203.0.113.21/32" {
		t.Errorf("cidrs = %v", got.CIDRs)
	}
	for _, it := range got.Items {
		if it.Address == "127.0.0.1" && (!it.Private || it.PoolName != "egress" || it.EndpointID != e0) {
			t.Errorf("exit item %+v", it)
		}
	}

	// Tenant B sees its own sensor only: no exit, no platform egress.
	gotB := h.scannerAddresses(adminB)
	if len(gotB.Items) != 1 || gotB.Items[0].Address != "203.0.113.30" || gotB.Items[0].SensorID != h.sensorB.String() {
		t.Fatalf("tenant B = %+v", gotB)
	}

	// Permissions: sensors:egress:read reads; sensors:read alone does not.
	h.scannerAddresses(ppCaller{Tenant: h.tenantA, Perms: []permission.Permission{permission.SensorEgressRead}})
	if status, _ := h.do(ppCaller{Tenant: h.tenantA, Perms: []permission.Permission{permission.SensorsRead}},
		http.MethodGet, "/api/v1/proxy-pools/scanner-addresses", nil); status != http.StatusForbidden {
		t.Fatalf("scanner addresses without sensors:egress:read = %d", status)
	}
}

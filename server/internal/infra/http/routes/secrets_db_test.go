package routes

// Task secrets (docs/architecture/task-secrets.md) over the real v2 routes
// and a migrated database: the refs a claimed job lists in its signed
// payload, and the sealed per-task fetch with every gate. The threat model:
// a sensor of another tenant, another sensor of the same tenant, a sensor
// that lost the lease, a bearer-key or untrusted or unconfined sensor, a
// replayed request, a TLS terminator that reads the answer, and an
// attacker with database write access but no key. Requires DATABASE_URL.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/contract/secretref"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/command"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/sensorproto/sealed"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// syncBuffer is a log sink safe for concurrent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const (
	secKeyA     = "tenant-a-shodan-key-00000001"
	secKeyA2    = "tenant-a-shodan-key-rotated2"
	secKeyB     = "tenant-b-shodan-key-00000002"
	secSTKeyA   = "tenant-a-securitytrails-0003"
	secProxyPwd = "proxy-pass-sealed-0001"
)

// secretsOf reads the secrets member of a job payload.
func secretsOf(t *testing.T, payload json.RawMessage) secretref.Set {
	t.Helper()
	var p struct {
		Secrets *secretref.Set `json:"secrets"`
	}
	if err := json.Unmarshal(payload, &p); err != nil || p.Secrets == nil {
		t.Fatalf("no secrets member: %v %s", err, payload)
	}
	if err := p.Secrets.Validate(); err != nil {
		t.Fatalf("secrets member invalid: %v", err)
	}
	return *p.Secrets
}

// keyBind makes s a key-bound sensor (its bearer key stops working) and
// returns its signing key. tenantID is "" for a shared sensor.
func (h *ctlHarness) keyBind(s ctlSensor, tenantID string) ed25519.PrivateKey {
	h.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	var tid any
	if tenantID != "" {
		tid = tenantID
	}
	if _, err := h.db.ExecContext(context.Background(), `INSERT INTO sensor_keys (tenant_id, sensor_id, thumbprint, public_key, status, activated_at)
		VALUES ($1, $2, $3, $4, 'active', now())`, tid, s.id, sensorsig.Thumbprint(pub), []byte(pub)); err != nil {
		h.t.Fatalf("bind key: %v", err)
	}
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensors SET auth_kind = 'key_bound' WHERE id = $1`, s.id); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensor_keys WHERE sensor_id = $1`, s.id)
	})
	return priv
}

func (h *ctlHarness) trustSensor(s ctlSensor) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensors SET trust_level = 'trusted' WHERE id = $1`, s.id); err != nil {
		h.t.Fatal(err)
	}
}

// confine records a shared sensor's full confinement: network confinement
// reported, and a manifest posture with the sandbox required and enforced.
func (h *ctlHarness) confine(s ctlSensor) {
	h.t.Helper()
	h.reportCaps(s, "net.confined@1")
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	digest := "sha256:" + hex.EncodeToString(b)
	if _, err := h.db.ExecContext(context.Background(), `INSERT INTO sensor_manifests (sensor_id, tenant_id, digest, source, manifest)
		SELECT id, tenant_id, $2, 'sensor', '{"posture":{"sandbox":{"mode":"required","sandboxed":true,"network_enforced":true}}}'::jsonb
		  FROM sensors WHERE id = $1`, s.id, digest); err != nil {
		h.t.Fatalf("manifest: %v", err)
	}
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensors SET manifest_digest = $2 WHERE id = $1`, s.id, digest); err != nil {
		h.t.Fatal(err)
	}
}

// signedDo makes a request signed by key (RFC 9421) with exactly body.
func (h *ctlHarness) signedDo(key ed25519.PrivateKey, method, path string, body []byte, hdr ...string) (*http.Response, []byte) {
	h.t.Helper()
	signer, err := sensorsig.NewSigner(key)
	if err != nil {
		h.t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("User-Agent", "openctem-sdk-go/0.47.0 (openctemio-sensor/0.30.0)")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	hc := &http.Client{Transport: &sensorsig.Transport{Signer: signer, Base: h.srv.Client().Transport}}
	resp, err := hc.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// fetched is one fetch: the answer as sent, and opened with the reply key.
type fetched struct {
	resp  *http.Response
	raw   []byte
	body  []byte
	reply *sealed.PrivateKey
	sa    secretref.SealedAnswer
	ans   secretref.Answer
}

func (f fetched) value(t *testing.T, id string) string {
	t.Helper()
	for _, s := range f.ans.Secrets {
		if s.ID == id {
			return string(s.Value)
		}
	}
	return ""
}

func (f fetched) missing(id string) string {
	for _, m := range f.ans.Missing {
		if m.ID == id {
			return m.Reason
		}
	}
	return ""
}

// fetchSecrets sends a fetch for refs under epoch, signed by key; a 200 is
// opened with the request's reply key.
func (h *ctlHarness) fetchSecrets(key ed25519.PrivateKey, sensorID, commandID string, epoch int64, refs ...string) fetched {
	h.t.Helper()
	reply, err := sealed.GenerateKey()
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := json.Marshal(secretref.FetchRequest{LeaseEpoch: epoch, Task: "t1", Refs: refs,
		ReplyKey: b64url(reply.Public().Bytes())})
	return h.sendFetch(key, sensorID, commandID, epoch, body, reply)
}

func (h *ctlHarness) sendFetch(key ed25519.PrivateKey, sensorID, commandID string, epoch int64, body []byte, reply *sealed.PrivateKey,
	hdr ...string,
) fetched {
	h.t.Helper()
	path := "/api/v2/sensor/commands/" + commandID + "/" + protov2.SecretsAction
	resp, raw := h.signedDo(key, http.MethodPost, path, body, hdr...)
	f := fetched{resp: resp, raw: raw, body: body, reply: reply}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound && !strings.Contains(string(raw), "command-not-found") {
			h.t.Fatalf("refusal is not command-not-found: %s", raw)
		}
		return f
	}
	if resp.Header.Get("Content-Type") != secretref.ContentType || resp.Header.Get("Cache-Control") != "no-store" {
		h.t.Fatalf("answer headers: %v", resp.Header)
	}
	if err := json.Unmarshal(raw, &f.sa); err != nil || f.sa.Validate(reply.Public().Bytes()) != nil {
		h.t.Fatalf("sealed answer: %v %s", err, raw)
	}
	ct, err := f.sa.SealedBytes()
	if err != nil {
		h.t.Fatal(err)
	}
	pt, err := sealed.OpenWithKey(reply, secretref.Info(sensorID, commandID, epoch, body), ct)
	if err != nil {
		h.t.Fatalf("answer does not open with the reply key: %v", err)
	}
	if err := json.Unmarshal(pt, &f.ans); err != nil {
		h.t.Fatal(err)
	}
	return f
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// runningJob creates a command of tenantID with payload, running for holder
// under lease epoch 3, and records its secrets as a claim does.
func (h *ctlHarness) runningJob(tenantID, holder, typ, payload string, shared bool) string {
	h.t.Helper()
	id := h.newCommand(tenantID, "")
	if _, err := h.db.ExecContext(context.Background(), `
		UPDATE commands SET type = $5, payload = $2::jsonb, is_platform_job = $4, status = 'running', sensor_id = $3, lease_epoch = 3,
		       acknowledged_at = now(), started_at = now(), lease_expires_at = now() + interval '10 minutes'
		WHERE id = $1`, id, payload, holder, shared, typ); err != nil {
		h.t.Fatalf("running job: %v", err)
	}
	cmd, err := h.cmds.Get(context.Background(), tenantID, id)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.secrets.GrantSecrets(context.Background(), cmd, *cmd.SensorID); err != nil {
		h.t.Fatalf("grant: %v", err)
	}
	return id
}

func (h *ctlHarness) setProviderKey(tenantID, source, value string) {
	h.t.Helper()
	if _, err := h.keys.StoreKey(context.Background(), tenantID, source, value, auditapp.AuditContext{TenantID: tenantID}); err != nil {
		h.t.Fatalf("set key: %v", err)
	}
}

const secSubfinderJob = `{"scanner":"subfinder","targets":["example.com","example.org"]}`

// noValues fails when any of the values appears in text.
func noValues(t *testing.T, what, text string, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(text, v) {
			t.Fatalf("%s holds a secret value", what)
		}
	}
}

// The whole path: a claim lists the refs (names only) in the signed
// payload and records them; the fetch answers them sealed to the reply key,
// readable by nothing else; audit and logs hold no value.
func TestTaskSecrets_ClaimListsRefsAndFetchIsSealed(t *testing.T) {
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	s := h.newSensor(h.tenantID, "sec-claim")
	s.tools = []string{"subfinder"}
	h.verifyTools(s)
	h.reportCaps(s, "net.confined@1", "egress.upstream@1")
	h.trustSensor(s)
	key := h.keyBind(s, h.tenantID)
	h.setProviderKey(h.tenantID, "shodan", secKeyA)
	h.setProviderKey(h.tenantID, "securitytrails", secSTKeyA)
	if _, err := h.keys.SwitchKey(context.Background(), h.tenantID, "securitytrails", false, auditapp.AuditContext{TenantID: h.tenantID}); err != nil {
		t.Fatal(err)
	}
	pool := h.newPool(h.tenantID, "corp", "socks5://alice:"+secProxyPwd+"@10.0.0.5:1080", true)
	c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: h.tenantID, SensorID: s.id, Type: "scan",
		Priority: "normal", Payload: json.RawMessage(`{"scanner":"subfinder","targets":["example.com"],"secrets":{"v":1,"local":"allow","refs":[]}}`),
		ExpiresIn: 3600})
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := h.signedDo(key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil,
		protov2.HeaderSensorFeatures, protov2.FeatureCapacity)
	h.want(resp, raw, http.StatusOK, "")
	got := decodeAs[protov2.CommandList](t, raw).Commands
	if len(got) != 1 || got[0].ID != c.ID.String() {
		t.Fatalf("claim: %s", raw)
	}
	noValues(t, "the job payload", string(got[0].Payload), secKeyA, secSTKeyA, secProxyPwd, "alice")
	set := secretsOf(t, got[0].Payload)
	k1, okK := set.Lookup("k1")
	p1, okP := set.Lookup("p1")
	if set.Local != secretref.LocalAllow || len(set.Refs) != 2 || !okK || k1.Ref != "shodan" || k1.Slot != "shodan" ||
		k1.Class != secretref.ClassProvider || !okP || p1.Ref != pool.ID.String() || p1.Local != secretref.LocalNever || !p1.Required {
		t.Fatalf("job secrets (the disabled key is not listed, a creator's member is replaced): %+v", set)
	}
	var fetches, maxFetches int
	if err := h.db.QueryRowContext(context.Background(), `SELECT fetches, max_fetches FROM command_secret_grants WHERE command_id = $1 AND lease_epoch = $2 AND tenant_id = $3`,
		c.ID.String(), got[0].LeaseEpoch, h.tenantID).Scan(&fetches, &maxFetches); err != nil || fetches != 0 || maxFetches != 3 {
		t.Fatalf("grant row: %d/%d %v", fetches, maxFetches, err)
	}

	epoch := int64(got[0].LeaseEpoch)
	f := h.fetchSecrets(key, s.id, c.ID.String(), epoch, "k1", "p1")
	if f.resp.StatusCode != http.StatusOK {
		t.Fatalf("lease holder: %d %s", f.resp.StatusCode, f.raw)
	}
	// What a TLS terminator or request log sees holds no value.
	noValues(t, "the raw answer", string(f.raw), secKeyA, secProxyPwd, "alice")
	if err := f.ans.Check(set, c.ID.String(), epoch, []string{"k1", "p1"}, f.ans.IssuedAt); err != nil {
		t.Fatalf("answer fails the sensor's check: %v", err)
	}
	if !strings.Contains(f.value(t, "k1"), secKeyA) || !strings.Contains(f.value(t, "p1"), secProxyPwd) {
		t.Fatalf("values: %+v", f.ans)
	}
	// It opens only with the reply key and only for this sensor, command,
	// epoch and request body.
	ct, _ := f.sa.SealedBytes()
	other, _ := sealed.GenerateKey()
	for name, c2 := range map[string]struct {
		k    *sealed.PrivateKey
		info []byte
	}{
		"another key":     {other, secretref.Info(s.id, c.ID.String(), epoch, f.body)},
		"another sensor":  {f.reply, secretref.Info(h.newSensor(h.tenantID, "x").id, c.ID.String(), epoch, f.body)},
		"another command": {f.reply, secretref.Info(s.id, h.newCommand(h.tenantID, ""), epoch, f.body)},
		"another epoch":   {f.reply, secretref.Info(s.id, c.ID.String(), epoch+1, f.body)},
		"another body":    {f.reply, secretref.Info(s.id, c.ID.String(), epoch, append(bytes.Clone(f.body), ' '))},
	} {
		if _, err := sealed.OpenWithKey(c2.k, c2.info, ct); err == nil {
			t.Errorf("%s: the answer opened", name)
		}
	}
	// A replay of the same body (a degraded nonce store) yields ciphertext
	// only the original reply key opens.
	again := h.sendFetch(key, s.id, c.ID.String(), epoch, f.body, f.reply)
	ct2, _ := again.sa.SealedBytes()
	if again.resp.StatusCode != http.StatusOK || bytes.Equal(ct, ct2) {
		t.Fatalf("replayed body: %d", again.resp.StatusCode)
	}
	if _, err := sealed.OpenWithKey(other, secretref.Info(s.id, c.ID.String(), epoch, f.body), ct2); err == nil {
		t.Fatal("a replay opened with another key")
	}

	// Audit: delivered, naming refs, never a value; the key marked used.
	var events string
	if err := h.db.QueryRowContext(context.Background(), `SELECT COALESCE(string_agg(action || ' ' || metadata::text || ' ' || COALESCE(message, ''), E'\n'), '')
		FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'secret.%'`, h.tenantID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(events, "secret.delivered") || !strings.Contains(events, `"k1"`) {
		t.Fatalf("delivery not audited: %s", events)
	}
	noValues(t, "the audit trail", events, secKeyA, secSTKeyA, secProxyPwd, f.sa.Sealed[:32])
	var used bool
	if err := h.db.QueryRowContext(context.Background(), `SELECT last_used_at IS NOT NULL FROM tool_source_keys WHERE tenant_id = $1 AND source = 'shodan'`,
		h.tenantID).Scan(&used); err != nil || !used {
		t.Fatalf("key use not recorded: %v", err)
	}
	noValues(t, "the logs", h.logs.String(), secKeyA, secSTKeyA, secProxyPwd)

	// The retired routes are gone.
	for _, gone := range []string{"egress-credentials", "tool-credentials"} {
		resp, _ := h.signedDo(key, http.MethodPost, "/api/v2/sensor/commands/"+c.ID.String()+"/"+gone, []byte(`{}`),
			protov2.HeaderLeaseEpoch, strconv.FormatInt(epoch, 10))
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", gone, resp.StatusCode)
		}
	}
}

func TestTaskSecrets_TenantIsolation(t *testing.T) {
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	tenantA, tenantB := h.tenantID, h.newTenant()
	h.setProviderKey(tenantA, "shodan", secKeyA)
	h.setProviderKey(tenantB, "shodan", secKeyB)
	sA := h.newSensor(tenantA, "iso-a")
	h.trustSensor(sA)
	keyA := h.keyBind(sA, tenantA)
	sB := h.newSensor(tenantB, "iso-b")
	h.trustSensor(sB)
	keyB := h.keyBind(sB, tenantB)

	jobA := h.runningJob(tenantA, sA.id, "scan", secSubfinderJob, false)
	jobB := h.runningJob(tenantB, sB.id, "scan", secSubfinderJob, false)
	if f := h.fetchSecrets(keyA, sA.id, jobA, 3, "k1"); f.resp.StatusCode != 200 || !strings.Contains(f.value(t, "k1"), secKeyA) {
		t.Fatalf("A's task: %d", f.resp.StatusCode)
	}
	if f := h.fetchSecrets(keyB, sB.id, jobB, 3, "k1"); f.resp.StatusCode != 200 || !strings.Contains(f.value(t, "k1"), secKeyB) {
		t.Fatalf("B's task: %d", f.resp.StatusCode)
	}
	// B's sensor on A's command: not found, nothing leaks.
	if f := h.fetchSecrets(keyB, sB.id, jobA, 3, "k1"); f.resp.StatusCode != http.StatusNotFound {
		t.Fatalf("B's sensor on A's job: %d", f.resp.StatusCode)
	} else {
		noValues(t, "a refusal", string(f.raw), secKeyA, secKeyB)
	}

	// A shared sensor gets each held job's tenant values only.
	sh := h.newSharedSensor("iso-shared")
	h.trustSensor(sh)
	h.confine(sh)
	keyS := h.keyBind(sh, "")
	shA := h.runningJob(tenantA, sh.id, "scan", secSubfinderJob, true)
	shB := h.runningJob(tenantB, sh.id, "scan", secSubfinderJob, true)
	for job, want := range map[string]string{shA: secKeyA, shB: secKeyB} {
		cmd, _ := h.cmds.Get(context.Background(), map[string]string{shA: tenantA, shB: tenantB}[job], job)
		set := secretsOfCommand(t, h, cmd)
		if set.Local != secretref.LocalNever {
			t.Fatalf("shared job local policy %q", set.Local)
		}
		f := h.fetchSecrets(keyS, sh.id, job, 3, "k1")
		if f.resp.StatusCode != 200 || !strings.Contains(f.value(t, "k1"), want) {
			t.Fatalf("shared sensor on %s: %d", job, f.resp.StatusCode)
		}
	}
	// ...and never an organization job it does not hold.
	if f := h.fetchSecrets(keyS, sh.id, jobA, 3, "k1"); f.resp.StatusCode != http.StatusNotFound {
		t.Fatalf("shared sensor on an organization job: %d", f.resp.StatusCode)
	}
}

// secretsOfCommand reads the grant recorded for cmd's claim.
func secretsOfCommand(t *testing.T, h *ctlHarness, cmd *commanddom.Command) secretref.Set {
	t.Helper()
	var refs string
	if err := h.db.QueryRowContext(context.Background(), `SELECT refs::text FROM command_secret_grants WHERE command_id = $1 AND lease_epoch = $2`,
		cmd.ID.String(), cmd.LeaseEpoch).Scan(&refs); err != nil {
		t.Fatal(err)
	}
	var set secretref.Set
	if err := json.Unmarshal([]byte(refs), &set); err != nil {
		t.Fatal(err)
	}
	return set
}

func TestTaskSecrets_LeaseGates(t *testing.T) {
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	h.setProviderKey(h.tenantID, "shodan", secKeyA)
	s := h.newSensor(h.tenantID, "lease-a")
	h.trustSensor(s)
	key := h.keyBind(s, h.tenantID)
	s2 := h.newSensor(h.tenantID, "lease-a2")
	h.trustSensor(s2)
	key2 := h.keyBind(s2, h.tenantID)
	job := h.runningJob(h.tenantID, s.id, "scan", secSubfinderJob, false)

	reply, _ := sealed.GenerateKey()
	headerOnly, _ := json.Marshal(map[string]any{"task": "t1", "refs": []string{"k1"}, "reply_key": b64url(reply.Public().Bytes())})
	for name, f := range map[string]func() fetched{
		"another sensor of the tenant": func() fetched { return h.fetchSecrets(key2, s2.id, job, 3, "k1") },
		"wrong epoch":                  func() fetched { return h.fetchSecrets(key, s.id, job, 4, "k1") },
		"old epoch":                    func() fetched { return h.fetchSecrets(key, s.id, job, 2, "k1") },
		"epoch only in a header": func() fetched {
			return h.sendFetch(key, s.id, job, 3, headerOnly, reply, protov2.HeaderLeaseEpoch, "3")
		},
	} {
		if got := f(); got.resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", name, got.resp.StatusCode)
		}
	}
	// A finished command gets nothing, same sensor and epoch.
	if f := h.fetchSecrets(key, s.id, job, 3, "k1"); f.resp.StatusCode != 200 {
		t.Fatalf("live: %d", f.resp.StatusCode)
	}
	for _, end := range []string{"completed", "failed", "canceled"} {
		if _, err := h.db.ExecContext(context.Background(), `UPDATE commands SET status = $2, completed_at = now() WHERE id = $1`, job, end); err != nil {
			t.Fatal(err)
		}
		if f := h.fetchSecrets(key, s.id, job, 3, "k1"); f.resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s command: %d", end, f.resp.StatusCode)
		}
	}
}

func TestTaskSecrets_SensorGates(t *testing.T) {
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	h.setProviderKey(h.tenantID, "shodan", secKeyA)

	// A bearer-key sensor: never answered (the reply key in its body is
	// not authenticated).
	bearer := h.newSensor(h.tenantID, "gate-bearer")
	h.trustSensor(bearer)
	job := h.runningJob(h.tenantID, bearer.id, "scan", secSubfinderJob, false)
	reply, _ := sealed.GenerateKey()
	body, _ := json.Marshal(secretref.FetchRequest{LeaseEpoch: 3, Refs: []string{"k1"}, ReplyKey: b64url(reply.Public().Bytes())})
	resp, raw := h.call(bearer.key, http.MethodPost, "/api/v2/sensor/commands/"+job+"/"+protov2.SecretsAction, body)
	h.want(resp, raw, http.StatusNotFound, ingestProblem("command-not-found"))

	// An untrusted (new) grant gets nothing, for a provider key AND for
	// the proxy pool's credentials.
	untrusted := h.newSensor(h.tenantID, "gate-new")
	h.reportCaps(untrusted, "net.confined@1", "egress.upstream@1")
	keyU := h.keyBind(untrusted, h.tenantID)
	pool := h.newPool(h.tenantID, "corp", "socks5://alice:"+secProxyPwd+"@10.0.0.5:1080", true)
	eg := `{"scanner":"subfinder","targets":["example.com"],"egress":{"mode":"pool","pool_id":"` + pool.ID.String() +
		`","endpoints":[{"id":"` + pool.Endpoints[0].ID.String() + `","auth":true}]}}`
	jobU := h.runningJob(h.tenantID, untrusted.id, "scan", eg, false)
	for _, ref := range []string{"k1", "p1"} {
		if f := h.fetchSecrets(keyU, untrusted.id, jobU, 3, ref); f.resp.StatusCode != http.StatusNotFound {
			t.Errorf("untrusted sensor, %s: %d", ref, f.resp.StatusCode)
		} else {
			noValues(t, "a refusal", string(f.raw), secKeyA, secProxyPwd)
		}
	}
	// Trusted, the same sensor gets both.
	h.trustSensor(untrusted)
	if f := h.fetchSecrets(keyU, untrusted.id, jobU, 3, "k1", "p1"); f.resp.StatusCode != 200 ||
		!strings.Contains(f.value(t, "p1"), secProxyPwd) {
		t.Fatalf("trusted: %d", f.resp.StatusCode)
	}

	// A shared sensor without the confinement posture gets nothing.
	sh := h.newSharedSensor("gate-shared")
	h.trustSensor(sh)
	keyS := h.keyBind(sh, "")
	shJob := h.runningJob(h.tenantID, sh.id, "scan", secSubfinderJob, true)
	if f := h.fetchSecrets(keyS, sh.id, shJob, 3, "k1"); f.resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unconfined shared sensor: %d", f.resp.StatusCode)
	}
	h.confine(sh)
	if f := h.fetchSecrets(keyS, sh.id, shJob, 3, "k1"); f.resp.StatusCode != 200 {
		t.Fatalf("confined shared sensor: %d", f.resp.StatusCode)
	}
}

func TestTaskSecrets_RefsAndFetchBound(t *testing.T) {
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	h.setProviderKey(h.tenantID, "shodan", secKeyA)
	s := h.newSensor(h.tenantID, "bound")
	h.trustSensor(s)
	key := h.keyBind(s, h.tenantID)
	job := h.runningJob(h.tenantID, s.id, "scan", secSubfinderJob, false)
	// A ref the claim did not record (no securitytrails key then).
	h.setProviderKey(h.tenantID, "securitytrails", secSTKeyA)
	if f := h.fetchSecrets(key, s.id, job, 3, "k2"); f.resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unrecorded ref: %d", f.resp.StatusCode)
	}
	if f := h.fetchSecrets(key, s.id, job, 3, "k1", "k2"); f.resp.StatusCode != http.StatusNotFound {
		t.Fatalf("one unrecorded ref among recorded: %d", f.resp.StatusCode)
	}
	// Two targets: 4 fetches, then refused and audited.
	for i := 0; i < 4; i++ {
		if f := h.fetchSecrets(key, s.id, job, 3, "k1"); f.resp.StatusCode != 200 {
			t.Fatalf("fetch %d: %d", i+1, f.resp.StatusCode)
		}
	}
	if f := h.fetchSecrets(key, s.id, job, 3, "k1"); f.resp.StatusCode != http.StatusNotFound {
		t.Fatalf("above max_fetches: %d", f.resp.StatusCode)
	}
	var reasons string
	if err := h.db.QueryRowContext(context.Background(), `SELECT COALESCE(string_agg(metadata->>'reason', ','), '') FROM audit_logs
		WHERE tenant_id = $1 AND action = 'secret.refused'`, h.tenantID).Scan(&reasons); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reasons, "max_fetches") || !strings.Contains(reasons, "ref_not_granted") {
		t.Fatalf("refusals audited: %q", reasons)
	}
}

// Values are read at fetch: a key disabled or rotated after the claim is
// answered as it is now.
func TestTaskSecrets_DisabledAndRotatedAfterClaim(t *testing.T) {
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	h.setProviderKey(h.tenantID, "shodan", secKeyA)
	s := h.newSensor(h.tenantID, "rotate")
	h.trustSensor(s)
	key := h.keyBind(s, h.tenantID)
	job := h.runningJob(h.tenantID, s.id, "scan", secSubfinderJob, false)
	actx := auditapp.AuditContext{TenantID: h.tenantID}
	if _, err := h.keys.SwitchKey(context.Background(), h.tenantID, "shodan", false, actx); err != nil {
		t.Fatal(err)
	}
	if f := h.fetchSecrets(key, s.id, job, 3, "k1"); f.resp.StatusCode != 200 || f.missing("k1") != secretref.MissingDisabled ||
		len(f.ans.Secrets) != 0 {
		t.Fatalf("disabled: %d %+v", f.resp.StatusCode, f.ans.Missing)
	}
	if _, err := h.keys.SwitchKey(context.Background(), h.tenantID, "shodan", true, actx); err != nil {
		t.Fatal(err)
	}
	h.setProviderKey(h.tenantID, "shodan", secKeyA2)
	if f := h.fetchSecrets(key, s.id, job, 3, "k1"); !strings.Contains(f.value(t, "k1"), secKeyA2) {
		t.Fatalf("rotated: %d", f.resp.StatusCode)
	}
}

// An attacker with database write access but no key cannot move a stored
// key to another row: the ciphertext opens only for its own tenant and
// source.
func TestTaskSecrets_StorageBinding(t *testing.T) {
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	tenantA, tenantB := h.tenantID, h.newTenant()
	h.setProviderKey(tenantA, "shodan", secKeyA)
	h.setProviderKey(tenantB, "shodan", secKeyB)
	h.setProviderKey(tenantB, "securitytrails", secSTKeyA)
	// Tenant B's rows now hold A's shodan ciphertext.
	if _, err := h.db.ExecContext(context.Background(), `UPDATE tool_source_keys SET key_enc = (SELECT key_enc FROM tool_source_keys WHERE tenant_id = $1 AND source = 'shodan')
		WHERE tenant_id = $2`, tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	sB := h.newSensor(tenantB, "bind-b")
	h.trustSensor(sB)
	keyB := h.keyBind(sB, tenantB)
	job := h.runningJob(tenantB, sB.id, "scan", secSubfinderJob, false)
	set := secretsOfCommand(t, h, mustCmd(t, h, tenantB, job))
	refs := make([]string, 0, len(set.Refs))
	for _, r := range set.Refs {
		refs = append(refs, r.ID)
	}
	f := h.fetchSecrets(keyB, sB.id, job, 3, refs...)
	if f.resp.StatusCode != 200 || len(f.ans.Secrets) != 0 || len(f.ans.Missing) != 2 {
		t.Fatalf("copied ciphertexts: %d %+v", f.resp.StatusCode, f.ans.Missing)
	}
	for _, m := range f.ans.Missing {
		if m.Reason != secretref.MissingUndecryptable {
			t.Fatalf("missing %+v", m)
		}
	}
}

func mustCmd(t *testing.T, h *ctlHarness, tenantID, id string) *commanddom.Command {
	t.Helper()
	c, err := h.cmds.Get(context.Background(), tenantID, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

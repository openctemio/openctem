package routes

// Signed jobs at claim time (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
// §5.6, docs/architecture/job-signing.md), over the real route registration
// and a migrated database: every command a claim hands a sensor carries an
// envelope whose statement binds the claimant, its tenant, the command, the
// lease epoch and the exact payload bytes of the response; a command the
// signer does not sign is not handed out; without a signer nothing changes.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/openctemio/openctem/api/internal/app/command"
	signerclient "github.com/openctemio/openctem/api/internal/infra/signer"
	"github.com/openctemio/openctem/api/internal/signer"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// wireCommand keeps the exact bytes of payload and signed_job as the
// response carried them (json.RawMessage copies them verbatim).
type wireCommand struct {
	ID         string          `json:"id"`
	SensorID   *string         `json:"sensor_id"`
	Status     string          `json:"status"`
	Payload    json.RawMessage `json:"payload"`
	LeaseEpoch int             `json:"lease_epoch"`
	SignedJob  json.RawMessage `json:"signed_job"`
}

type wireCommandList struct {
	Commands []wireCommand `json:"commands"`
}

// testKeySetRoot is the offline root that signs realSigner's key set.
var testKeySetRoot = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))

// realSigner runs the signer service (internal/signer) on a Unix socket,
// with a key set signed by testKeySetRoot, and returns the API's client of
// it and the signer's public key.
func realSigner(t *testing.T) (*signerclient.Client, ed25519.PublicKey) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sj") // short: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := signer.New(signer.Config{Key: priv, StateDir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	keyset, _, err := jobsign.SignKeySet(testKeySetRoot, 1, time.Now(), 24*time.Hour, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LoadKeySet(keyset); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	ln, err := signer.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := signer.NewHTTPServer(svc.Handler())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = svc.Close() })
	return signerclient.NewClient(sock, 2*time.Second), pub
}

// fakeSigner signs like the signer, or fails with err.
type fakeSigner struct {
	mu   sync.Mutex
	key  ed25519.PrivateKey
	err  error
	seq  uint64
	seen []jobsign.Statement
}

func newFakeSigner(t *testing.T) (*fakeSigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSigner{key: priv}, pub
}

func (f *fakeSigner) SignJob(_ context.Context, st jobsign.Statement) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, st)
	if f.err != nil {
		return nil, f.err
	}
	f.seq++
	st.Seq, st.Nonce = f.seq, "n"
	pub, _ := f.key.Public().(ed25519.PublicKey)
	st.Signer = &jobsign.SignerRef{KeyID: jobsign.KeyID(pub)}
	payload, _ := json.Marshal(st)
	return json.Marshal(jobsign.Sign(f.key, payload))
}

func (f *fakeSigner) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func (f *fakeSigner) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// verifySignedJob checks c's envelope against pub and that its statement
// binds the claimant, the tenant, the command, the lease epoch and the exact
// payload bytes of the response. It returns the statement.
func verifySignedJob(t *testing.T, c wireCommand, pub ed25519.PublicKey, tenantID, sensorID string) *jobsign.Statement {
	t.Helper()
	if len(c.SignedJob) == 0 {
		t.Fatalf("command %s handed out without signed_job", c.ID)
	}
	st, err := jobsign.Verify(c.SignedJob, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("signed_job of %s: %v", c.ID, err)
	}
	if st.TenantID != tenantID || st.SensorID != sensorID || st.CommandID != c.ID {
		t.Fatalf("statement ids %s/%s/%s, want %s/%s/%s", st.TenantID, st.SensorID, st.CommandID, tenantID, sensorID, c.ID)
	}
	if st.PayloadSHA256 != jobsign.PayloadDigest(c.Payload) {
		t.Fatalf("payload_sha256 %s does not match the payload bytes %s", st.PayloadSHA256, c.Payload)
	}
	if st.LeaseEpoch != c.LeaseEpoch || st.LeaseEpoch < 1 {
		t.Fatalf("statement lease epoch %d, command %d", st.LeaseEpoch, c.LeaseEpoch)
	}
	if st.CommandType != "scan" || st.Tool != "semgrep" || len(st.Targets) != 1 || st.Targets[0] != "." {
		t.Fatalf("statement %+v does not describe the command", st)
	}
	if !st.ExpiresAt.After(st.IssuedAt) || st.ExpiresAt.Sub(st.IssuedAt) > jobsign.MaxTTL {
		t.Fatalf("expiry %s..%s", st.IssuedAt, st.ExpiresAt)
	}
	return st
}

func TestSignedJobs_V2ClaimsCarryEnvelopesFromTheSigner(t *testing.T) {
	client, pub := realSigner(t)
	h := newCtlHarness(t, command.WithJobSigner(client))
	h.results.SetSignedJobs(client.Hello)
	s := h.newSensor(h.tenantID, "signed")
	h.setMaxJobs(s.id, 5)
	first := h.newCommand(h.tenantID, "")

	// A listing poll is not a claim: no envelope.
	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil)
	h.want(resp, raw, 200, "")
	if strings.Contains(string(raw), "signed_job") {
		t.Fatalf("a listing poll carried a signed job: %s", raw)
	}

	// Claim-N: signed, bound to this sensor, its tenant and the payload bytes.
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	list := decodeAs[wireCommandList](t, raw)
	if len(list.Commands) != 1 || list.Commands[0].ID != first {
		t.Fatalf("claim-N: %s", raw)
	}
	st1 := verifySignedJob(t, list.Commands[0], pub, h.tenantID, s.id)

	// Its claim by id is a replay, signed again with a later seq.
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+first+"/claim", nil)
	h.want(resp, raw, 200, "")
	st2 := verifySignedJob(t, decodeAs[wireCommand](t, raw), pub, h.tenantID, s.id)
	if st2.Seq <= st1.Seq || st2.Nonce == st1.Nonce {
		t.Fatalf("replay seq %d nonce %s after %d %s", st2.Seq, st2.Nonce, st1.Seq, st1.Nonce)
	}

	// A fresh claim by id.
	second := h.newCommand(h.tenantID, "")
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+second+"/claim", nil)
	h.want(resp, raw, 200, "")
	verifySignedJob(t, decodeAs[wireCommand](t, raw), pub, h.tenantID, s.id)

	// Other transitions answer the command without an envelope.
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+second+"/start", nil)
	h.want(resp, raw, 200, "")
	if strings.Contains(string(raw), "signed_job") {
		t.Fatalf("start carried a signed job: %s", raw)
	}

	// Hello advertises signing and the signer's key.
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/hello", nil)
	h.want(resp, raw, 200, "")
	hello := decodeAs[protov2.Hello](t, raw)
	if !protov2.HasFeature([]string{strings.Join(hello.Features, ",")}, protov2.FeatureSignedJobs) {
		t.Fatalf("hello features %v lack signed_jobs", hello.Features)
	}
	if hello.SignedJobs == nil || hello.SignedJobs.PayloadType != jobsign.PayloadType || len(hello.SignedJobs.Keys) != 1 ||
		hello.SignedJobs.Keys[0].KeyID != jobsign.KeyID(pub) {
		t.Fatalf("hello signed_jobs %s", raw)
	}
	// And the key set: signed by the offline root, listing the signer's key.
	rootPub, _ := testKeySetRoot.Public().(ed25519.PublicKey)
	ks, _, err := jobsign.VerifyKeySet(hello.SignedJobs.KeySet, jobsign.KeyID(rootPub), time.Now())
	if err != nil || !ks.HasKey(jobsign.KeyID(pub)) {
		t.Fatalf("hello signed_jobs.keyset %s: %v", hello.SignedJobs.KeySet, err)
	}
}

func TestSignedJobs_SignerFailureHandsOutNothing(t *testing.T) {
	fake, _ := newFakeSigner(t)
	h := newCtlHarness(t, command.WithJobSigner(fake))
	s := h.newSensor(h.tenantID, "refused")
	h.setMaxJobs(s.id, 5)
	unpinned := h.newCommand(h.tenantID, "")
	pinned := h.newCommand(h.tenantID, s.id)

	for _, failure := range []error{errors.New("signer down"), command.ErrJobRefused} {
		fake.fail(failure)
		asked := fake.calls()
		resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
		h.want(resp, raw, 200, "")
		if l := decodeAs[wireCommandList](t, raw); len(l.Commands) != 0 {
			t.Fatalf("%v: unsigned commands handed out: %s", failure, raw)
		}
		// A signer that does not answer is asked once per claim, not once
		// per command; one that refuses is asked for each.
		want := 1
		if errors.Is(failure, command.ErrJobRefused) {
			want = 2
		}
		if got := fake.calls() - asked; got != want {
			t.Fatalf("%v: signer asked %d times for 2 commands, want %d", failure, got, want)
		}
		// Taken back: pending, the unpinned one unpinned again, the pinned
		// one still the sensor's only.
		if st, sensor, leased := h.commandState(unpinned); st != "pending" || sensor != nil || leased {
			t.Fatalf("%v: unpinned command %s %v leased=%v", failure, st, sensor, leased)
		}
		if st, sensor, leased := h.commandState(pinned); st != "pending" || sensor == nil || *sensor != s.id || leased {
			t.Fatalf("%v: pinned command %s %v leased=%v", failure, st, sensor, leased)
		}

		// A claim by id answers 503 and leaves the command pending.
		resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+unpinned+"/claim", nil)
		h.want(resp, raw, http.StatusServiceUnavailable, protov2.ProblemUnavailable.URI())
		if st, sensor, _ := h.commandState(unpinned); st != "pending" || sensor != nil {
			t.Fatalf("%v: after a refused claim: %s %v", failure, st, sensor)
		}
	}

	// The signer is back: the same commands go out, signed.
	fake.fail(nil)
	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	l := decodeAs[wireCommandList](t, raw)
	if len(l.Commands) != 2 {
		t.Fatalf("after recovery: %s", raw)
	}
	for _, c := range l.Commands {
		if len(c.SignedJob) == 0 {
			t.Fatalf("unsigned after recovery: %s", raw)
		}
	}
}

func TestSignedJobs_NoSignerLeavesClaimsUnchanged(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "plain")
	h.setMaxJobs(s.id, 5)
	h.newCommand(h.tenantID, "")
	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	if l := decodeAs[wireCommandList](t, raw); len(l.Commands) != 1 || strings.Contains(string(raw), "signed_job") {
		t.Fatalf("claim-N without a signer: %s", raw)
	}
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/hello", nil)
	h.want(resp, raw, 200, "")
	if strings.Contains(string(raw), "signed_job") {
		t.Fatalf("hello advertises signing without a signer: %s", raw)
	}
}

func TestSignedJobs_V3ClaimCommands(t *testing.T) {
	fake, pub := newFakeSigner(t)
	h := newV3HarnessWith(t, []command.Option{command.WithJobSigner(fake)})
	tid := h.newTenant()
	a := h.newKeyBound(tid)
	ctx := context.Background()

	for _, grpc := range []bool{false, true} {
		fake.fail(nil)
		cmdID := h.newCommand(tid, "")
		claimed, err := h.client(a, grpc).ClaimCommands(ctx, connect.NewRequest(&sensorv3.ClaimCommandsRequest{Limit: 5}))
		if err != nil {
			t.Fatalf("claim (grpc=%v): %v", grpc, err)
		}
		list := decodeAs[wireCommandList](t, claimed.Msg.GetCommandsJson())
		if len(list.Commands) != 1 || list.Commands[0].ID != cmdID {
			t.Fatalf("claimed %s", claimed.Msg.GetCommandsJson())
		}
		verifySignedJob(t, list.Commands[0], pub, tid, a.id)

		// The signer fails: the next command is not handed out.
		fake.fail(errors.New("signer down"))
		next := h.newCommand(tid, "")
		claimed, err = h.client(a, grpc).ClaimCommands(ctx, connect.NewRequest(&sensorv3.ClaimCommandsRequest{Limit: 5}))
		if err != nil {
			t.Fatalf("claim with the signer down (grpc=%v): %v", grpc, err)
		}
		if l := decodeAs[wireCommandList](t, claimed.Msg.GetCommandsJson()); len(l.Commands) != 0 {
			t.Fatalf("unsigned command handed out over v3: %s", claimed.Msg.GetCommandsJson())
		}
		var status string
		_ = h.db.QueryRow(`SELECT status FROM commands WHERE id = $1`, next).Scan(&status)
		if status != "pending" {
			t.Fatalf("unsigned command left %s", status)
		}
		h.exec(`DELETE FROM commands WHERE id = $1`, next)
	}
}

package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

const (
	tTenant  = "11111111-1111-4111-8111-111111111111"
	tSensor  = "22222222-2222-4222-8222-22222222abcd"
	tSensor2 = "44444444-4444-4444-8444-444444444444"
	tCommand = "33333333-3333-4333-8333-333333333333"
)

var tNow = time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func newService(t *testing.T, dir string, key ed25519.PrivateKey, mod func(*Config)) *Service {
	t.Helper()
	// These tests are about the statement, the sequence and the log: the
	// ledger is off unless a test turns it on (ledger_test.go).
	cfg := Config{Key: key, StateDir: dir, Now: func() time.Time { return tNow }, LedgerMode: jobsign.LedgerOff}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// statement is a valid statement as a JSON object, with edits applied.
func statement(edit func(m map[string]any)) []byte {
	m := map[string]any{
		"kind": jobsign.Kind, "tenant_id": tTenant, "sensor_id": tSensor, "command_id": tCommand,
		"command_type": "scan", "tool": "nuclei", "payload_sha256": jobsign.PayloadDigest([]byte(`{"a":1}`)),
		"targets": []string{"203.0.113.10", "app.example.com"}, "lease_epoch": 2,
		"issued_at": tNow.Format(time.RFC3339Nano), "expires_at": tNow.Add(time.Hour).Format(time.RFC3339Nano),
	}
	if edit != nil {
		edit(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestSign_RefusesInvalidStatements(t *testing.T) {
	cases := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"missing tenant", statement(func(m map[string]any) { delete(m, "tenant_id") }), ReasonInvalidID},
		{"missing sensor", statement(func(m map[string]any) { delete(m, "sensor_id") }), ReasonInvalidID},
		{"missing command", statement(func(m map[string]any) { delete(m, "command_id") }), ReasonInvalidID},
		{"non-uuid sensor", statement(func(m map[string]any) { m["sensor_id"] = "../../etc/passwd" }), ReasonInvalidID},
		{"upper-case uuid", statement(func(m map[string]any) { m["sensor_id"] = strings.ToUpper(tSensor) }), ReasonInvalidID},
		{"bad kind", statement(func(m map[string]any) { m["kind"] = "openctem.job/v2" }), ReasonBadKind},
		{"missing command type", statement(func(m map[string]any) { delete(m, "command_type") }), ReasonMissingType},
		{"missing tool", statement(func(m map[string]any) { delete(m, "tool") }), ReasonMissingTool},
		{"null tool", statement(func(m map[string]any) { m["tool"] = nil }), ReasonMissingTool},
		{"bad digest", statement(func(m map[string]any) { m["payload_sha256"] = "sha256:abc" }), ReasonBadDigest},
		{"upper-case digest", statement(func(m map[string]any) {
			m["payload_sha256"] = strings.ToUpper(jobsign.PayloadDigest(nil))
		}), ReasonBadDigest},
		{"missing targets", statement(func(m map[string]any) { delete(m, "targets") }), ReasonBadTargets},
		{"too many targets", statement(func(m map[string]any) {
			ts := make([]string, jobsign.MaxTargets+1)
			for i := range ts {
				ts[i] = "h"
			}
			m["targets"] = ts
		}), ReasonBadTargets},
		{"target too long", statement(func(m map[string]any) {
			m["targets"] = []string{strings.Repeat("a", jobsign.MaxTargetBytes+1)}
		}), ReasonBadTargets},
		{"negative lease epoch", statement(func(m map[string]any) { m["lease_epoch"] = -1 }), ReasonBadLeaseEpoch},
		{"issued in the future", statement(func(m map[string]any) {
			m["issued_at"] = tNow.Add(3 * time.Minute).Format(time.RFC3339)
			m["expires_at"] = tNow.Add(30 * time.Minute).Format(time.RFC3339)
		}), ReasonClockSkew},
		{"issued in the past", statement(func(m map[string]any) {
			m["issued_at"] = tNow.Add(-3 * time.Minute).Format(time.RFC3339)
		}), ReasonClockSkew},
		{"expiry over an hour", statement(func(m map[string]any) {
			m["expires_at"] = tNow.Add(time.Hour + time.Second).Format(time.RFC3339)
		}), ReasonBadExpiry},
		{"expiry before issue", statement(func(m map[string]any) {
			m["expires_at"] = tNow.Format(time.RFC3339)
		}), ReasonBadExpiry},
		{"seq set by the caller", statement(func(m map[string]any) { m["seq"] = 99 }), ReasonServerField},
		{"nonce set by the caller", statement(func(m map[string]any) { m["nonce"] = "x" }), ReasonServerField},
		{"signer set by the caller", statement(func(m map[string]any) { m["signer"] = map[string]string{"keyid": "x"} }), ReasonServerField},
		{"unknown field", statement(func(m map[string]any) { m["scope_override"] = true }), ReasonMalformed},
		{"not json", []byte("nope"), ReasonMalformed},
		{"trailing data", append(statement(nil), []byte(` {}`)...), ReasonMalformed},
		{"oversize", append(statement(nil), bytes.Repeat([]byte(" "), jobsign.MaxStatementBytes)...), ReasonBodyTooLarge},
	}
	s := newService(t, t.TempDir(), newKey(t), nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, ref := s.Sign(tc.raw)
			if ref == nil {
				t.Fatalf("signed an invalid statement: %s", env)
			}
			if ref.reason != tc.reason || ref.status < 400 || ref.status >= 500 {
				t.Fatalf("refused with %d %s, want 4xx %s", ref.status, ref.reason, tc.reason)
			}
		})
	}
	if _, ref := s.Sign(statement(nil)); ref != nil {
		t.Fatalf("the valid statement was refused: %+v", ref)
	}
	// An empty tool and no targets are a valid command that names neither.
	if _, ref := s.Sign(statement(func(m map[string]any) { m["tool"] = ""; m["targets"] = []string{} })); ref != nil {
		t.Fatalf("an empty tool and target list were refused: %+v", ref)
	}
}

func TestSign_RateCeilings(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), func(c *Config) {
		c.TenantRate, c.TenantBurst, c.SensorRate, c.SensorBurst = 0.001, 4, 0.001, 2
	})
	for i := 0; i < 2; i++ {
		if _, ref := s.Sign(statement(nil)); ref != nil {
			t.Fatalf("sign %d refused: %+v", i, ref)
		}
	}
	if _, ref := s.Sign(statement(nil)); ref == nil || ref.reason != ReasonSensorRate || ref.status != http.StatusTooManyRequests {
		t.Fatalf("third sign for one sensor: %+v, want the sensor ceiling", ref)
	}
	// The refused sign still spent a tenant token (3 of 4). Another sensor of
	// the tenant has its own bucket; then the tenant ceiling is reached.
	other := statement(func(m map[string]any) { m["sensor_id"] = tSensor2 })
	if _, ref := s.Sign(other); ref != nil {
		t.Fatalf("other sensor refused: %+v", ref)
	}
	if _, ref := s.Sign(other); ref == nil || ref.reason != ReasonTenantRate {
		t.Fatalf("past the tenant burst: %+v, want the tenant ceiling", ref)
	}
}

func decodeEnvelope(t *testing.T, env []byte) (scannertemplate.Envelope, jobsign.Statement) {
	t.Helper()
	var e scannertemplate.Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	var st jobsign.Statement
	if err := json.Unmarshal(e.Payload, &st); err != nil {
		t.Fatal(err)
	}
	return e, st
}

func TestSign_EnvelopeVerifiesOverExactPayloadBytes(t *testing.T) {
	key := newKey(t)
	s := newService(t, t.TempDir(), key, nil)
	env, ref := s.Sign(statement(nil))
	if ref != nil {
		t.Fatal(ref)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	st, err := jobsign.Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.TenantID != tTenant || st.SensorID != tSensor || st.CommandID != tCommand || st.LeaseEpoch != 2 ||
		st.Tool != "nuclei" || st.CommandType != "scan" || len(st.Targets) != 2 {
		t.Fatalf("statement changed in signing: %+v", st)
	}
	if st.Seq != 1 || st.Signer == nil || st.Signer.KeyID != jobsign.KeyID(pub) || !strings.HasPrefix(st.Signer.KeyID, "SHA256:") {
		t.Fatalf("server fields: seq %d signer %+v", st.Seq, st.Signer)
	}
	if n, err := base64.RawURLEncoding.DecodeString(st.Nonce); err != nil || len(n) != jobsign.NonceBytes {
		t.Fatalf("nonce %q", st.Nonce)
	}

	e, _ := decodeEnvelope(t, env)
	if e.PayloadType != jobsign.PayloadType || len(e.Signatures) != 1 || e.Signatures[0].KeyID != jobsign.KeyID(pub) {
		t.Fatalf("envelope %s", env)
	}
	// The signature is over PAE(type, the exact payload bytes).
	if !ed25519.Verify(pub, scannertemplate.PreAuthEncoding(jobsign.PayloadType, e.Payload), e.Signatures[0].Sig) {
		t.Fatal("signature does not cover the payload bytes")
	}
	// Any change to the bytes, even one a JSON re-encoding would hide, fails.
	e.Payload = append(e.Payload, ' ')
	tampered, _ := json.Marshal(e)
	if _, err := jobsign.Verify(tampered, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("a changed payload verified")
	}
	other, _ := newKey(t).Public().(ed25519.PublicKey)
	if _, err := jobsign.Verify(env, []ed25519.PublicKey{other}); err == nil {
		t.Fatal("verified with an untrusted key")
	}
}

func TestSign_SeqIncreasesPerSensorAndSurvivesRestart(t *testing.T) {
	dir, key := t.TempDir(), newKey(t)
	s := newService(t, dir, key, nil)
	seqOf := func(s *Service, raw []byte) uint64 {
		env, ref := s.Sign(raw)
		if ref != nil {
			t.Fatal(ref)
		}
		_, st := decodeEnvelope(t, env)
		return st.Seq
	}
	other := statement(func(m map[string]any) { m["sensor_id"] = tSensor2 })
	if a, b, c := seqOf(s, statement(nil)), seqOf(s, statement(nil)), seqOf(s, other); a != 1 || b != 2 || c != 1 {
		t.Fatalf("seq %d %d (other sensor %d), want 1 2 (1)", a, b, c)
	}
	_ = s.Close()

	// A restart continues from what was stored.
	s2 := newService(t, dir, key, nil)
	if got := seqOf(s2, statement(nil)); got != 3 {
		t.Fatalf("after restart seq %d, want 3", got)
	}
	// A corrupt sequence file stops signing for that sensor instead of
	// restarting at 1.
	_ = s2.Close()
	if err := os.WriteFile(filepath.Join(dir, "seq", tSensor), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3 := newService(t, dir, key, nil)
	if _, ref := s3.Sign(statement(nil)); ref == nil || ref.status != http.StatusInternalServerError {
		t.Fatalf("signed with a corrupt sequence file: %+v", ref)
	}
}

func TestLoadKey_RefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signer.pem")
	pub, err := GenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o400 {
		t.Fatalf("keygen wrote mode %o, want 0400", fi.Mode().Perm())
	}
	priv, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatal("loaded a different key")
	}
	if _, err := GenerateKey(path); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	for _, mode := range []os.FileMode{0o440, 0o404, 0o640, 0o600 | 0o004} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKey(path); !errors.Is(err, ErrKeyFilePermissions) {
			t.Fatalf("mode %o: %v, want refused", mode, err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err != nil {
		t.Fatalf("mode 0600: %v", err)
	}
}

func TestSigningLog_ChainLinksEveryDecision(t *testing.T) {
	dir := t.TempDir()
	s := newService(t, dir, newKey(t), nil)
	if _, ref := s.Sign(statement(nil)); ref != nil {
		t.Fatal(ref)
	}
	if _, ref := s.Sign(statement(func(m map[string]any) { m["payload_sha256"] = "x" })); ref == nil {
		t.Fatal("signed a bad digest")
	}
	if _, ref := s.Sign(statement(nil)); ref != nil {
		t.Fatal(ref)
	}
	_ = s.Close()

	path := filepath.Join(dir, "signing.log")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("log has %d lines, want 3:\n%s", len(lines), raw)
	}
	var entries []LogEntry
	for _, l := range lines {
		var e LogEntry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	if entries[0].Prev != GenesisHash || entries[1].Prev != lineHash([]byte(lines[0])) || entries[2].Prev != lineHash([]byte(lines[1])) {
		t.Fatal("entries are not chained")
	}
	if entries[0].Decision != DecisionSigned || entries[0].Seq != 1 || entries[0].StatementSHA256 == "" ||
		entries[0].TenantID != tTenant || entries[0].SensorID != tSensor || entries[0].CommandID != tCommand {
		t.Fatalf("signed entry %+v", entries[0])
	}
	if entries[1].Decision != DecisionRefused || entries[1].Reason != ReasonBadDigest {
		t.Fatalf("refusal entry %+v", entries[1])
	}
	if _, n, err := VerifyLog(bytes.NewReader(raw)); err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}

	// Editing a line breaks the chain, and the signer refuses to start on it.
	edited := strings.Replace(string(raw), `"refused"`, `"signed"`, 1)
	if _, _, err := VerifyLog(strings.NewReader(edited)); err == nil {
		t.Fatal("an edited log verified")
	}
	removed := lines[0] + "\n" + lines[2] + "\n"
	if _, _, err := VerifyLog(strings.NewReader(removed)); err == nil {
		t.Fatal("a log with a line removed verified")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Key: newKey(t), StateDir: dir}); err == nil {
		t.Fatal("the signer started on a broken log")
	}
	if err := os.WriteFile(path, []byte(lines[0]), 0o600); err != nil { // torn: no newline
		t.Fatal(err)
	}
	if _, err := New(Config{Key: newKey(t), StateDir: dir}); err == nil {
		t.Fatal("the signer started on a torn log")
	}
}

func TestServe_UnixSocketOnly(t *testing.T) {
	dir, err := os.MkdirTemp("", "sig") // short path: socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	key := newKey(t)
	s := newService(t, filepath.Join(dir, "state"), key, nil)
	sock := filepath.Join(dir, "s.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTPServer(s.Handler())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if fi, _ := os.Lstat(sock); fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != SocketMode {
		t.Fatalf("socket mode %v", fi.Mode())
	}

	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	do := func(method, path string, body []byte) (*http.Response, error) {
		req, err := http.NewRequestWithContext(context.Background(), method, "http://signer"+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return c.Do(req)
	}
	resp, err := do(http.MethodPost, SignPath, statement(nil))
	if err != nil {
		t.Fatal(err)
	}
	var env bytes.Buffer
	_, _ = env.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	pub, _ := key.Public().(ed25519.PublicKey)
	if resp.StatusCode != 200 {
		t.Fatalf("sign: %d %s", resp.StatusCode, env.String())
	}
	if _, err := jobsign.Verify(env.Bytes(), []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	resp, err = do(http.MethodPost, SignPath, statement(func(m map[string]any) { delete(m, "tenant_id") }))
	if err != nil {
		t.Fatal(err)
	}
	var r jobsign.Refusal
	_ = json.NewDecoder(resp.Body).Decode(&r)
	_ = resp.Body.Close()
	if resp.StatusCode != 400 || r.Reason != ReasonInvalidID {
		t.Fatalf("refusal: %d %+v", resp.StatusCode, r)
	}

	resp, err = do(http.MethodGet, KeysPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	var keys jobsign.KeysResponse
	_ = json.NewDecoder(resp.Body).Decode(&keys)
	_ = resp.Body.Close()
	if len(keys.Keys) != 1 || keys.PayloadType != jobsign.PayloadType {
		t.Fatalf("keys %+v", keys)
	}
	if got, err := keys.Keys[0].Decode(); err != nil || !got.Equal(pub) {
		t.Fatalf("key %v %v", got, err)
	}

	// A path that is not a socket is never replaced.
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(plain); err == nil {
		t.Fatal("listened over a regular file")
	}
}

// A refused statement may carry anything: its log line stays bounded and
// holds only well-formed ids, so the log still verifies on restart.
func TestSigningLog_RefusalsAreBounded(t *testing.T) {
	dir, key := t.TempDir(), newKey(t)
	s := newService(t, dir, key, nil)
	huge := strings.Repeat("x", 200<<10)
	if _, ref := s.Sign(statement(func(m map[string]any) {
		m["kind"] = "bad"
		m["tool"] = huge
		m["command_type"] = huge
		m["payload_sha256"] = huge
		m["sensor_id"] = "evil\nline"
	})); ref == nil || ref.reason != ReasonBadKind {
		t.Fatalf("refusal %+v", ref)
	}
	_ = s.Close()
	raw, err := os.ReadFile(filepath.Join(dir, "signing.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 4<<10 {
		t.Fatalf("a refusal wrote a %d-byte log line", len(raw))
	}
	var e LogEntry
	if err := json.Unmarshal(bytes.TrimSpace(raw), &e); err != nil {
		t.Fatal(err)
	}
	if e.SensorID != "" || e.TenantID != tTenant {
		t.Fatalf("logged ids %q %q", e.SensorID, e.TenantID)
	}
	newService(t, dir, key, nil) // the log verifies
}

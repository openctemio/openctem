package systemstatus

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func certPEM(t *testing.T, notAfter time.Time, withKey bool) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: t0.Add(-time.Hour), NotAfter: notAfter,
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}}, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-material")})
	if !withKey {
		out = nil
	}
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStorageLevels(t *testing.T) {
	for _, tc := range []struct {
		free float64
		want int
	}{{0.5, LevelOK}, {0.20, LevelOK}, {0.19, LevelWarning}, {0.10, LevelWarning}, {0.09, LevelCritical}, {0, LevelCritical}} {
		if got := storageLevel(tc.free); got != tc.want {
			t.Errorf("free %.2f = %d, want %d", tc.free, got, tc.want)
		}
	}
}

func TestVolumesReportNameNotPath(t *testing.T) {
	dir := t.TempDir()
	c := New(Config{StoragePaths: []NamedPath{{"data", dir}, {"gone", filepath.Join(dir, "missing")}}}, Deps{Now: func() time.Time { return t0 }})
	s := c.Collect(context.Background())
	if len(s.Storage.Volumes) != 2 || !s.Storage.Volumes[0].OK || s.Storage.Volumes[0].TotalB == 0 || s.Storage.Volumes[1].OK {
		t.Fatalf("volumes = %+v", s.Storage.Volumes)
	}
	if v := s.Storage.Volumes[0]; v.FreeRatio <= 0 || v.FreeRatio > 1 || v.UsedB+v.FreeB > v.TotalB+v.FreeB {
		t.Fatalf("ratio = %+v", v)
	}
	if strings.Contains(mustJSON(t, s), dir) {
		t.Fatal("a file path leaked into the snapshot")
	}
}

func TestBackupAge(t *testing.T) {
	dir := t.TempDir()
	mk := func(ago time.Duration, exit int) Backup {
		body := "openctem_backup_last_exit_code " + itoa(exit) + "\nopenctem_backup_last_success_timestamp_seconds " + itoa(int(t0.Add(-ago).Unix())) + "\n"
		p := write(t, dir, "b.prom", body)
		return New(Config{BackupStatusFile: p}, Deps{Now: func() time.Time { return t0 }}).backup(t0)
	}
	if b := mk(2*time.Hour, 0); !b.Reported || b.Level != LevelOK || b.AgeSeconds != 7200 {
		t.Fatalf("fresh = %+v", b)
	}
	if b := mk(27*time.Hour, 0); b.Level != LevelWarning {
		t.Fatalf("stale = %+v", b)
	}
	if b := mk(2*time.Hour, 1); !b.LastFailed || b.Level != LevelOK {
		t.Fatalf("failed run = %+v", b)
	}
	if b := New(Config{}, Deps{}).backup(t0); b.Reported {
		t.Fatalf("unconfigured = %+v", b)
	}
	big := write(t, dir, "big.prom", strings.Repeat("x", maxFileBytes+1))
	if b := New(Config{BackupStatusFile: big}, Deps{}).backup(t0); b.Reported {
		t.Fatalf("oversize file read: %+v", b)
	}
}

func TestCertificatesExpiryAndKeySkipped(t *testing.T) {
	dir := t.TempDir()
	ca := write(t, dir, "ca.pem", string(certPEM(t, t0.Add(100*24*time.Hour), true)))
	soon := write(t, dir, "soon.pem", string(certPEM(t, t0.Add(10*24*time.Hour), false)))
	crit := write(t, dir, "crit.pem", string(certPEM(t, t0.Add(2*24*time.Hour), false)))
	c := New(Config{SensorCAFile: ca, TLSCertFiles: []NamedPath{{"edge", soon}, {"old", crit}, {"nofile", filepath.Join(dir, "none")}}}, Deps{})
	got := map[string]Certificate{}
	for _, ce := range c.certificates(t0) {
		got[ce.Name] = ce
	}
	if got["sensor-ca"].Level != LevelOK || got["edge"].Level != LevelWarning || got["old"].Level != LevelCritical || got["nofile"].OK {
		t.Fatalf("certs = %+v", got)
	}
	if strings.Contains(mustJSON(t, got), "secret-key") {
		t.Fatal("key material leaked")
	}
}

func TestProbesReportCodesOnly(t *testing.T) {
	var hits atomic.Int32
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "db password is hunter2", 500) }))
	defer bad.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, ok.URL, 302) }))
	defer redir.Close()
	n := hits.Load()
	c := New(Config{WebHealthURL: ok.URL, GatewayHealthURL: bad.URL}, Deps{
		PingDB:    func(context.Context) error { return nil },
		PingRedis: func(context.Context) error { return errors.New("dial tcp 10.0.0.5:6379: secret") },
		Sensors:   func(context.Context) (int64, int64, error) { return 3, 2, nil },
	})
	s := c.Collect(context.Background())
	by := map[string]Service{}
	for _, sv := range s.Services {
		by[sv.Name] = sv
	}
	if !by["api"].OK || !by["postgres"].OK || by["redis"].OK || by["redis"].Code != CodeUnreachable ||
		!by["web"].OK || by["gateway"].Code != CodeUnhealthy || !by["sensors"].OK || by["sensors"].Detail != 2 {
		t.Fatalf("services = %+v", by)
	}
	if s.Level != LevelCritical {
		t.Fatalf("level = %d", s.Level)
	}
	if j := mustJSON(t, s); strings.Contains(j, "hunter2") || strings.Contains(j, "10.0.0.5") || strings.Contains(j, ok.URL) {
		t.Fatalf("detail leaked: %s", j)
	}
	// A redirect is not followed.
	if r := New(Config{WebHealthURL: redir.URL}, Deps{}).httpProbe(context.Background(), "web", redir.URL); r.OK || hits.Load() != n+1 {
		t.Fatalf("redirect followed: %+v hits=%d", r, hits.Load())
	}
	// Unset URL: not configured, not a fault.
	if sv := New(Config{}, Deps{}).httpProbe(context.Background(), "web", ""); sv.Configured || sv.OK {
		t.Fatalf("unset = %+v", sv)
	}
}

func TestParseNamed(t *testing.T) {
	got := ParseNamed(" data=/var/x , bad, =x, y= ,log\n=/l ")
	if len(got) != 2 || got[0] != (NamedPath{"data", "/var/x"}) || got[1].Name != "log" {
		t.Fatalf("got %+v", got)
	}
}

type fakeNotifier struct{ subjects []string }

func (f *fakeNotifier) NotifyAdmins(_ context.Context, subject, _ string) error {
	f.subjects = append(f.subjects, subject)
	return nil
}

func TestWatcherMailsOnWorseNotOnRepeat(t *testing.T) {
	dir := t.TempDir()
	now := t0
	age := 2 * time.Hour
	status := func() {
		write(t, dir, "b.prom", "openctem_backup_last_success_timestamp_seconds "+itoa(int(now.Add(-age).Unix()))+"\n")
	}
	status()
	c := New(Config{BackupStatusFile: filepath.Join(dir, "b.prom")}, Deps{Now: func() time.Time { return now }})
	n := &fakeNotifier{}
	w := NewWatcher(c, n, time.Minute, logger.NewNop())
	w.now = func() time.Time { return now }
	run := func() int { k, _ := w.Reconcile(context.Background()); return k }

	if run() != 0 || len(n.subjects) != 0 {
		t.Fatal("a fresh backup must not mail")
	}
	age = 30 * time.Hour
	status()
	if run() != 1 || len(n.subjects) != 1 || !strings.Contains(n.subjects[0], "WARNING") {
		t.Fatalf("stale backup: %v", n.subjects)
	}
	now = now.Add(time.Hour)
	run()
	if len(n.subjects) != 1 {
		t.Fatal("same level inside 24 h must not mail again")
	}
	now = now.Add(RenotifyAfter)
	status()
	run()
	if len(n.subjects) != 2 {
		t.Fatalf("after 24 h it reminds: %v", n.subjects)
	}
	age = time.Hour
	status()
	run()
	age = 40 * time.Hour
	status()
	run()
	if len(n.subjects) != 3 {
		t.Fatalf("recovery then relapse mails again: %v", n.subjects)
	}
}

func TestWatcherMailsCriticalDisk(t *testing.T) {
	// A critical certificate stands in for a full disk (statfs cannot be faked).
	dir := t.TempDir()
	p := write(t, dir, "c.pem", string(certPEM(t, t0.Add(24*time.Hour), false)))
	n := &fakeNotifier{}
	w := NewWatcher(New(Config{TLSCertFiles: []NamedPath{{"edge", p}}}, Deps{Now: func() time.Time { return t0 }}), n, time.Minute, logger.NewNop())
	if _, err := w.Reconcile(context.Background()); err != nil || len(n.subjects) != 1 || !strings.Contains(n.subjects[0], "CRITICAL") {
		t.Fatalf("subjects = %v err=%v", n.subjects, err)
	}
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWatcherIsExclusive(t *testing.T) {
	if !(&Watcher{}).Exclusive() {
		t.Fatal("watcher must run on one replica only")
	}
}

func TestProbeClientIgnoresProxyAndRedirects(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	c := newProbeClient()
	if c.Timeout != probeTimeout {
		t.Fatalf("timeout = %v", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("probe transport must not use a proxy")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	if c.CheckRedirect(req, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects must not be followed")
	}
	// A reachable target still works although the env proxy is unreachable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("get via env proxy path: %v", err)
	}
	_ = resp.Body.Close()
}

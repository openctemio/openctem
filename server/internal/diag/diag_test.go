package diag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/systemstatus"
	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/diag/redact"
)

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func findCheck(t *testing.T, r Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q in %v", id, r.Checks)
	return Check{}
}

func TestQueryShape_RemovesEveryLiteral(t *testing.T) {
	cases := []struct{ in, want string }{
		{`SELECT id FROM assets WHERE name = 'Payroll Server 01' AND tenant_id = $1`, `SELECT id FROM assets WHERE name = ? AND tenant_id = $1`},
		{`select * from users where email='jane@example.com' and age > 42 limit 10`, `select * from users where email=? and age > ? limit ?`},
		{`INSERT INTO t (a, b) VALUES ('it''s secret', 3.14)`, `INSERT INTO t (a, b) VALUES (?, ?)`},
		{`SELECT E'tab\'s secret', 'next'`, `SELECT E?, ?`},
		{`SELECT 'ends with backslash\', 'second secret'`, `SELECT ?, ?`},
		{`SELECT $body$ secret body $body$, $$another$$, col1 FROM t2`, `SELECT ?, ?, col1 FROM t2`},
		{`SELECT 1 -- secret comment` + "\n" + `FROM t /* hidden 'note' */ WHERE x = 2`, `SELECT ? FROM t WHERE x = ?`},
		{`UPDATE "assets" SET "Display Name" = 'x' WHERE id IN (1, 2, 3)`, `UPDATE "assets" SET "?" = ? WHERE id IN (?, ?, ?)`},
		{`SELECT * FROM t WHERE note = 'cut off in the midd`, `SELECT * FROM t WHERE note = ?`},
		{`SELECT pg_sleep(30), 'x' FROM generate_series(1, 5)`, `SELECT pg_sleep(?), ? FROM generate_series(?, ?)`},
		{"SELECT 'tên' , ü", `SELECT ? , ??`},
		{``, ``},
	}
	for _, tc := range cases {
		if got := QueryShape(tc.in); got != tc.want {
			t.Errorf("QueryShape(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	long := QueryShape("SELECT " + strings.Repeat("col, ", 500) + "x FROM t")
	if len(long) > maxShapeLen+8 {
		t.Errorf("shape of %d bytes not cut", len(long))
	}
}

func TestEffectiveConfig_AllowList(t *testing.T) {
	reg := config.Registry()
	env := map[string]string{
		"APP_ENV":            "production",
		"LOG_LEVEL":          "debug",
		"DB_MAX_OPEN_CONNS":  "25",
		"APP_URL":            "https://ctem.customer.example",
		"DB_HOST":            "db01.customer.example",
		"DB_USER":            "ctem_owner",
		"DB_NAME":            "customer_ctem",
		"DB_PASSWORD":        "Sup3rS3cretDbPassw0rd",
		"APP_ENCRYPTION_KEY": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"FINGERPRINT_KEY":    "fedcba9876543210fedcba9876543210",
		"AUTH_JWT_SECRET":    "short",
		"METRICS_TOKEN":      "12345",
		"LOG_FORMAT":         "json; DROP",
		"NOT_A_REGISTERED":   "whatever-value",
	}
	entries := EffectiveConfig(reg, envOf(env))
	out := string(mustJSON(entries))
	for name, value := range env {
		shown := name == "APP_ENV" || name == "LOG_LEVEL" || name == "DB_MAX_OPEN_CONNS"
		if got := strings.Contains(out, `"`+value+`"`); got != shown {
			t.Errorf("%s: value shown = %v, want %v", name, got, shown)
		}
	}
	if strings.Contains(out, "NOT_A_REGISTERED") {
		t.Error("an unregistered variable is listed")
	}
	byName := map[string]ConfigEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if e := byName["DB_PASSWORD"]; !e.Set || e.Value != nil {
		t.Errorf("DB_PASSWORD = %+v, want set without a value", e)
	}
	if e := byName["REDIS_PASSWORD"]; e.Set || e.Value != nil {
		t.Errorf("REDIS_PASSWORD = %+v, want not set", e)
	}

	// No secret is ever shown, whatever its value looks like, and no URL,
	// path, list or unlisted string.
	all := map[string]string{}
	for _, v := range reg.Vars {
		all[v.Name] = "7"
	}
	for _, e := range EffectiveConfig(reg, envOf(all)) {
		v, _ := reg.Lookup(e.Name)
		wantShown := !v.Secret && (shownTypes[v.Type] || shownStrings[v.Name])
		if (e.Value != nil) != wantShown {
			t.Errorf("%s (type %s, secret %v): shown = %v", e.Name, v.Type, v.Secret, e.Value != nil)
		}
	}
	for name := range shownStrings {
		v, ok := reg.Lookup(name)
		if !ok || v.Secret {
			t.Errorf("allow-listed %s is not a registered non-secret setting", name)
		}
	}
}

func TestRun_ConfigurationThatDoesNotLoad(t *testing.T) {
	secret := "postgres://owner:Sup3rS3cret@db.customer.example/ctem"
	r := Run(context.Background(), Deps{
		ConfigErr: errors.New("DB_SSLMODE: invalid value for " + secret),
		Getenv:    envOf(map[string]string{"APP_ENV": "production"}),
	})
	if r.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1", r.ExitCode())
	}
	if c := findCheck(t, r, "config.valid"); c.Status != StatusFail || c.Fix == "" {
		t.Errorf("config.valid = %+v", c)
	}
	if c := findCheck(t, r, "database.reachable"); c.Status != StatusInfo {
		t.Errorf("database.reachable = %+v, want info (not checked)", c)
	}
	for _, id := range []string{"config.base_url", "config.encryption_key", "config.fingerprint_key"} {
		if c := findCheck(t, r, id); c.Status != StatusFail || c.Fix == "" {
			t.Errorf("%s = %+v, want fail with a fix", id, c)
		}
	}
	// The detail is shown to the operator as it is, and masked in a bundle.
	var table bytes.Buffer
	r.WriteTable(&table)
	if !strings.Contains(table.String(), "db.customer.example") {
		t.Error("the operator's own table lost the detail")
	}
	masked := string(mustJSON(r.Redacted(redact.NewWithKey([]byte("k")))))
	for _, s := range []string{"Sup3rS3cret", "db.customer.example", "owner"} {
		if strings.Contains(masked, s) {
			t.Errorf("%q survived in the bundle's report", s)
		}
	}
}

func TestChecks_KeysNeverPrinted(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fp := "fingerprint-key-of-at-least-32-characters"
	d := Deps{Getenv: envOf(map[string]string{"APP_ENCRYPTION_KEY": key, "FINGERPRINT_KEY": fp, "SENSOR_KEY_PEPPER": "pepper-value-123"})}
	checks := d.checkKeys()
	out := string(mustJSON(checks))
	for _, s := range []string{key, key[:8], fp, "pepper-value"} {
		if strings.Contains(out, s) {
			t.Errorf("key material %q in %s", s, out)
		}
	}
	if checks[0].Status != StatusPass || checks[1].Status != StatusPass {
		t.Errorf("well-formed keys not accepted: %+v", checks[:2])
	}
	for _, name := range []string{"APP_ENCRYPTION_KEY", "FINGERPRINT_KEY", "SENSOR_KEY_PEPPER"} {
		if !strings.Contains(checks[2].Summary, name) {
			t.Errorf("the keys to keep do not name %s", name)
		}
	}

	bad := Deps{Getenv: envOf(map[string]string{"APP_ENCRYPTION_KEY": "too-short", "FINGERPRINT_KEY": "short", "APP_ENV": "production"})}.checkKeys()
	if bad[0].Status != StatusFail || bad[1].Status != StatusFail {
		t.Errorf("malformed keys accepted: %+v", bad[:2])
	}
	if strings.Contains(string(mustJSON(bad)), "too-short") {
		t.Error("a malformed key is printed")
	}
}

func TestChecks_BaseURL(t *testing.T) {
	for raw, want := range map[string]Status{
		"":                                 StatusFail,
		"https://ctem.example.com":         StatusPass,
		"https://ctem.example.com:8443/":   StatusPass,
		"http://ctem.example.com":          StatusWarn,
		"https://ctem.example.com/console": StatusWarn,
		"https://u:p@ctem.example.com":     StatusWarn,
		"ctem.example.com":                 StatusFail,
		"ftp://ctem.example.com":           StatusFail,
	} {
		c := Deps{Getenv: envOf(map[string]string{"APP_URL": raw, "APP_ENV": "production"})}.checkBaseURL()
		if c.Status != want {
			t.Errorf("APP_URL=%q: %s, want %s", raw, c.Status, want)
		}
		if strings.Contains(c.Summary+c.Fix, "ctem.example.com/console") || strings.Contains(c.Summary, "u:p") {
			t.Errorf("APP_URL=%q: the value is printed: %+v", raw, c)
		}
	}
}

func TestChecks_SystemSnapshot(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	snap := &systemstatus.Snapshot{
		Storage: systemstatus.Storage{Volumes: []systemstatus.Volume{
			{Name: "attachments", OK: true, FreeRatio: 0.55},
			{Name: "db", OK: true, FreeRatio: 0.07, Level: systemstatus.LevelCritical},
			{Name: "gone"},
		}},
		Backup: systemstatus.Backup{Reported: true, AgeSeconds: 30 * 3600, Level: systemstatus.LevelWarning},
		Certificates: []systemstatus.Certificate{
			{Name: "gateway", OK: true, ExpiresInSecs: 5 * 86400, Level: systemstatus.LevelCritical},
			{Name: "sensor-ca", OK: true, ExpiresInSecs: 300 * 86400},
		},
		Services: []systemstatus.Service{
			{Name: "web", Configured: true, OK: false, Code: systemstatus.CodeUnreachable},
			{Name: "gateway"},
		},
	}
	d := Deps{Now: func() time.Time { return now }}
	if c := d.checkStorage(snap); c.Status != StatusFail || !strings.Contains(c.Summary, "(db) has 7% free") || c.Fix == "" {
		t.Errorf("storage = %+v", c)
	}
	if c := d.checkBackup(snap); c.Status != StatusWarn || !strings.Contains(c.Summary, "30 hours") {
		t.Errorf("backup = %+v", c)
	}
	if c := d.checkBackup(&systemstatus.Snapshot{}); c.Status != StatusInfo {
		t.Errorf("unreported backup = %+v, want info", c)
	}
	certs := d.checkCertificates(context.Background(), snap)
	if certs[0].Status != StatusFail || !strings.Contains(certs[0].Summary, "5 days left") {
		t.Errorf("certificate files = %+v", certs[0])
	}
	if certs[1].Status != StatusInfo {
		t.Errorf("public certificate without a probe = %+v, want info", certs[1])
	}
	svc := d.checkServices(snap)
	if len(svc) != 1 || svc[0].ID != "service.web" || svc[0].Status != StatusWarn {
		t.Errorf("services = %+v", svc)
	}

	// The certificate the public URL serves.
	cfg := &config.Config{}
	cfg.App.URL = "https://ctem.example.com"
	for left, want := range map[time.Duration]Status{
		90 * 24 * time.Hour: StatusPass, 20 * 24 * time.Hour: StatusWarn, 3 * 24 * time.Hour: StatusFail, -time.Hour: StatusFail,
	} {
		var asked string
		d := Deps{Config: cfg, Now: func() time.Time { return now },
			CertExpiry: func(_ context.Context, hp string) (time.Time, error) { asked = hp; return now.Add(left), nil }}
		got := d.checkCertificates(context.Background(), nil)[1]
		if got.Status != want || asked != "ctem.example.com:443" {
			t.Errorf("%v left: %+v (asked %q), want %s", left, got, asked, want)
		}
		if strings.Contains(got.Summary, "ctem.example.com") {
			t.Errorf("the host is printed: %q", got.Summary)
		}
	}
	unreachable := Deps{Config: cfg, CertExpiry: func(context.Context, string) (time.Time, error) {
		return time.Time{}, errors.New("dial tcp 192.0.2.1:443: i/o timeout")
	}}.checkCertificates(context.Background(), nil)[1]
	if unreachable.Status != StatusInfo {
		t.Errorf("unreachable public URL = %+v, want info", unreachable)
	}
}

func TestReport_Output(t *testing.T) {
	r := Report{Checks: []Check{
		{ID: "a", Name: "A", Status: StatusPass, Summary: "Fine."},
		{ID: "b", Name: "B", Status: StatusWarn, Summary: "Look.", Fix: "Do this."},
		{ID: "c", Name: "C", Status: StatusInfo, Summary: "Fact."},
	}, Passed: 1, Warnings: 1}
	if r.ExitCode() != 0 {
		t.Fatal("warnings must not fail the command")
	}
	var b bytes.Buffer
	r.WriteTable(&b)
	for _, want := range []string{"STATUS", "PASS", "WARN", "fix: Do this.", "1 passed, 1 warnings, 0 failed"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	if err := r.WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b.Bytes(), &back); err != nil || len(back.Checks) != 3 || back.Checks[1].Fix != "Do this." {
		t.Fatalf("JSON does not round-trip: %v %+v", err, back)
	}
	r.Failed = 1
	if r.ExitCode() != 1 {
		t.Fatal("a failed check must fail the command")
	}
}

func TestWriteBundle_Limits(t *testing.T) {
	red := redact.NewWithKey([]byte("k"))
	if _, err := WriteBundle(context.Background(), &bytes.Buffer{}, BundleInput{Redactor: red, MaxSize: 10}); err == nil {
		t.Error("a 10 byte limit accepted")
	}
	if _, err := WriteBundle(context.Background(), &bytes.Buffer{}, BundleInput{MaxSize: DefaultMaxSize}); err == nil {
		t.Error("a bundle without a redactor accepted")
	}

	// 4 MiB of log lines into a 256 KiB bundle: the newest lines stay, the
	// archive fits.
	var logs bytes.Buffer
	line := func(i int) string {
		return `{"time":"2026-11-17T10:00:00Z","level":"INFO","msg":"line ` + strings.Repeat("x", 180) + `","n":` + itoa(i) + `}` + "\n"
	}
	n := 0
	for logs.Len() < 4<<20 {
		logs.WriteString(line(n))
		n++
	}
	var archive bytes.Buffer
	m, err := WriteBundle(context.Background(), &archive, BundleInput{
		Redactor: red, MaxSize: MinMaxSize, Logs: &logs, Since: time.Hour,
		Now: func() time.Time { return time.Date(2026, 11, 17, 10, 30, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if archive.Len() > MinMaxSize {
		t.Fatalf("archive of %d bytes over the %d limit", archive.Len(), MinMaxSize)
	}
	files := untar(t, archive.Bytes())
	got := string(files["logs/server.log"])
	if !strings.Contains(got, `"n":`+itoa(n-1)+`,`) || strings.Contains(got, `"n":0,`) {
		t.Error("the newest lines were not the ones kept")
	}
	if len(got) > MinMaxSize {
		t.Errorf("%d bytes of logs kept", len(got))
	}
	if !strings.Contains(strings.Join(m.Notes, "\n"), "oldest lines cut") {
		t.Errorf("notes do not say lines were cut: %v", m.Notes)
	}

	// The time limit stops the reading, and the note says so.
	done, cancel := context.WithCancel(context.Background())
	cancel()
	archive.Reset()
	m, err = WriteBundle(done, &archive, BundleInput{Redactor: red, Logs: strings.NewReader("a line\n"), Since: time.Hour})
	if err != nil || !strings.Contains(strings.Join(m.Notes, "\n"), "time limit") {
		t.Errorf("a bundle past its time limit: %v, notes %v", err, m.Notes)
	}

	// --since drops older lines; lines without a time follow the line before.
	logs.Reset()
	logs.WriteString(`{"time":"2026-11-17T06:00:00Z","msg":"old line"}` + "\n  continuation of the old line\n" +
		`{"time":"2026-11-17T10:10:00Z","msg":"new line"}` + "\n  continuation of the new line\n")
	archive.Reset()
	if _, err := WriteBundle(context.Background(), &archive, BundleInput{
		Redactor: red, Logs: &logs, Since: time.Hour,
		Now: func() time.Time { return time.Date(2026, 11, 17, 10, 30, 0, 0, time.UTC) },
	}); err != nil {
		t.Fatal(err)
	}
	got = string(untar(t, archive.Bytes())["logs/server.log"])
	if strings.Contains(got, "old line") || !strings.Contains(got, "new line") || !strings.Contains(got, "continuation of the new line") {
		t.Errorf("--since kept the wrong lines:\n%s", got)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

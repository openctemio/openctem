package sensor

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// contractChecks is the check catalog v0 every sensor-side emitter shares
// (research/26 §3; sdk-go pkg/sensorkit and openctemio/sensor emit these
// ids and codes). The platform catalog must explain each one, and nothing
// else: a new id or code is added here and in the catalog together.
var contractChecks = map[string][]string{
	"tool.*.binary":              {"ok", "not_installed", "broken", "check_error"},
	"tool.*.selection":           {"not_selected", "policy_excluded"},
	"tool.*.registration":        {"register_failed"},
	"tools.available":            {"ok", "none"},
	"identity.state_persistent":  {"persistent", "not_persistent", "unknown"},
	"identity.key_renewal":       {"enabled", "disabled", "off_not_persistent", "start_failed"},
	"network.scan_proxy_inherit": {"direct", "inherit_explicit", "inherits_proxy"},
	"runtime.oom_protect":        {"protected", "not_requested", "unsupported", "no_permission", "failed"},
	"config.alias_deprecated":    {"legacy_name"},
	"config.env_unknown":         {"unknown"},
	"platform.tls":               {"ok", "ca_file_unreadable", "ca_dir_unreadable"},
	"policy.local":               {"enforced", "absent"},
	"policy.template_keys":       {"ok", "not_needed", "missing"},
	"runtime.command_poller":     {"running", "stopped"},
	// openctemio/sensor
	"config.file_unknown_key":  {"unknown_key"},
	"config.file_unset_var":    {"unset_var"},
	"config.commands_disabled": {"daemon_without_commands"},
	"config.tool_retired":      {"retired_name"},
}

func TestConfigCheckCatalog_CoversTheContractExactly(t *testing.T) {
	var want []string
	for id, codes := range contractChecks {
		for _, c := range codes {
			want = append(want, id+" "+c)
		}
	}
	slices.Sort(want)
	got := catalogKeys()
	for _, k := range want {
		if !slices.Contains(got, k) {
			t.Errorf("catalog has no entry for %q", k)
		}
	}
	for _, k := range got {
		if !slices.Contains(want, k) {
			t.Errorf("catalog entry %q is not in the contract", k)
		}
	}
	seen := map[string]bool{}
	for _, k := range got {
		if seen[k] {
			t.Errorf("duplicate catalog entry %q", k)
		}
		seen[k] = true
	}
}

// fullParams are values for every parameter a catalog text may name.
func fullParams() map[string]sensordom.ConfigParam {
	n := int64(2)
	return map[string]sensordom.ConfigParam{
		"tool": {Name: "semgrep"}, "path": {Path: "/var/lib/openctem/state"}, "name": {Name: "SSL_CERT_FILE"},
		"replacement": {Name: "SENSOR_TOOLS"}, "suggestion": {Name: "SENSOR_MAX_JOBS"}, "key": {Name: "max_job"},
		"vars": {Names: []string{"HTTPS_PROXY", "NO_PROXY"}}, "count": {Int: &n}, "exit_code": {Int: &n},
	}
}

func TestConfigCheckCatalog_EveryEntryRenders(t *testing.T) {
	for _, e := range configCheckCatalog {
		id := strings.ReplaceAll(e.ID, "*", "semgrep")
		ex := ExplainCheck(sensordom.ConfigCheck{ID: id, Code: e.Code, Params: fullParams()})
		if !ex.Known || ex.Title == "" || ex.Why == "" || !slices.Contains(ConfigCheckGroups, ex.Group) ||
			!strings.HasPrefix(ex.DocsURL, configCheckDocsBase) || e.Docs == "" {
			t.Errorf("%s %s: %+v", e.ID, e.Code, ex)
		}
		if strings.Contains(ex.Title+ex.Why, "{") || strings.Contains(ex.Why, "(not reported)") {
			t.Errorf("%s %s: unresolved placeholder in %q / %q", e.ID, e.Code, ex.Title, ex.Why)
		}
		if len(ex.Fix) != len(e.Fix) {
			t.Errorf("%s %s: rendered %d of %d fix formats", e.ID, e.Code, len(ex.Fix), len(e.Fix))
		}
		for format, snippet := range ex.Fix {
			if !slices.Contains([]string{FixFormatEnv, FixFormatCompose, FixFormatHelm}, format) {
				t.Errorf("%s %s: unknown format %s", e.ID, e.Code, format)
			}
			if format != FixFormatEnv {
				var v any
				if err := yaml.Unmarshal([]byte(snippet), &v); err != nil {
					t.Errorf("%s %s %s: not YAML: %v\n%s", e.ID, e.Code, format, err, snippet)
				}
			}
		}
	}
}

func TestExplainCheck_UnknownCheckIsNotExplained(t *testing.T) {
	for _, c := range []sensordom.ConfigCheck{
		{ID: "content.templates_signed", Code: "missing"},     // a newer sensor's id
		{ID: "identity.state_persistent", Code: "new_code"},   // a known id with an unknown code
		{ID: "storage.disk_space", Code: "low", Summary: "x"}, // group from the id
	} {
		ex := ExplainCheck(c)
		if ex.Known || ex.Title != c.ID || ex.Why != "" || len(ex.Fix) != 0 || ex.DocsURL != "" {
			t.Errorf("%s/%s explained: %+v", c.ID, c.Code, ex)
		}
	}
	if g := ExplainCheck(sensordom.ConfigCheck{ID: "storage.disk_space"}).Group; g != "storage" {
		t.Errorf("group %s", g)
	}
	if g := ExplainCheck(sensordom.ConfigCheck{ID: "weird.thing"}).Group; g != "config" {
		t.Errorf("group %s", g)
	}
}

func TestExplainCheck_WhyIsPlainTextAndFixIsEscaped(t *testing.T) {
	// The sanitizer never lets quotes-and-newlines through a path, but the
	// renderer must not depend on that: escaping is per format either way.
	hostile := "/srv/st'ate\"\n$(reboot)`id`"
	c := sensordom.ConfigCheck{ID: "identity.state_persistent", Code: "not_persistent",
		Params: map[string]sensordom.ConfigParam{"path": {Path: hostile}}}
	ex := ExplainCheck(c)
	if !strings.Contains(ex.Why, hostile) {
		t.Fatalf("why must carry the value as plain text: %q", ex.Why)
	}
	// A line break in a value could end a comment line of the env snippet:
	// the env format is left out instead.
	if env, ok := ex.Fix[FixFormatEnv]; ok {
		t.Fatalf("env fix rendered a value with a line break:\n%s", env)
	}
	quoted := "/srv/st'ate\"$(reboot)`id`"
	exq := ExplainCheck(sensordom.ConfigCheck{ID: "identity.state_persistent", Code: "not_persistent",
		Params: map[string]sensordom.ConfigParam{"path": {Path: quoted}}})
	if want := "export SENSOR_STATE_DIR=" + shellQuote(quoted) + "\n"; !strings.Contains(exq.Fix[FixFormatEnv]+"\n", want) {
		t.Fatalf("env fix not shell-quoted:\n%s", exq.Fix[FixFormatEnv])
	}
	var doc struct {
		Services struct {
			Sensor struct {
				Volumes []string `yaml:"volumes"`
			} `yaml:"sensor"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(ex.Fix[FixFormatCompose]), &doc); err != nil {
		t.Fatalf("compose fix is not YAML: %v\n%s", err, ex.Fix[FixFormatCompose])
	}
	if got := doc.Services.Sensor.Volumes; len(got) != 1 || got[0] != "state:"+hostile {
		t.Fatalf("compose volume %q, want the value as one scalar", got)
	}

	// A host parameter in the TLS fix: YAML-quoted inside the helm values.
	tls := ExplainCheck(sensordom.ConfigCheck{ID: "platform.tls", Code: "ca_file_unreadable",
		Params: map[string]sensordom.ConfigParam{"name": {Name: "SSL_CERT_FILE"}, "path": {Path: "/etc/x: y\n- z"}}})
	var helm struct {
		Sensor struct {
			Mounts []struct {
				MountPath string `yaml:"mountPath"`
			} `yaml:"extraVolumeMounts"`
		} `yaml:"sensor"`
	}
	if err := yaml.Unmarshal([]byte(tls.Fix[FixFormatHelm]), &helm); err != nil || len(helm.Sensor.Mounts) != 1 ||
		helm.Sensor.Mounts[0].MountPath != "/etc/x: y\n- z" {
		t.Fatalf("helm fix %v %+v\n%s", err, helm, tls.Fix[FixFormatHelm])
	}
}

func TestExplainCheck_FormatNeedingAMissingParamIsLeftOut(t *testing.T) {
	// No path: the state fixes that mount {path} cannot be rendered; helm
	// needs none.
	ex := ExplainCheck(sensordom.ConfigCheck{ID: "identity.state_persistent", Code: "not_persistent"})
	if _, ok := ex.Fix[FixFormatEnv]; ok {
		t.Errorf("env fix rendered without a path: %q", ex.Fix[FixFormatEnv])
	}
	if _, ok := ex.Fix[FixFormatCompose]; ok {
		t.Errorf("compose fix rendered without a path")
	}
	if ex.Fix[FixFormatHelm] == "" {
		t.Errorf("helm fix missing")
	}
	if !strings.Contains(ex.Why, "(not reported)") {
		t.Errorf("why %q", ex.Why)
	}
	// The wildcard of tool.*.binary stands in for a missing tool param.
	if ex := ExplainCheck(sensordom.ConfigCheck{ID: "tool.nuclei.binary", Code: "not_installed"}); !strings.Contains(ex.Title, "nuclei") {
		t.Errorf("title %q", ex.Title)
	}
	// An optional parameter (suggestion) is used when present only.
	with := ExplainCheck(sensordom.ConfigCheck{ID: "config.env_unknown", Code: "unknown", Params: map[string]sensordom.ConfigParam{
		"name": {Name: "SENSOR_MAX_JOB"}, "suggestion": {Name: "SENSOR_MAX_JOBS"}}})
	without := ExplainCheck(sensordom.ConfigCheck{ID: "config.env_unknown", Code: "unknown", Params: map[string]sensordom.ConfigParam{
		"name": {Name: "SENSOR_MAX_JOB"}}})
	if !strings.Contains(with.Fix[FixFormatEnv], "Did you mean 'SENSOR_MAX_JOBS'") || strings.Contains(without.Fix[FixFormatEnv], "Did you mean") ||
		!strings.Contains(without.Fix[FixFormatEnv], "unset 'SENSOR_MAX_JOB'") {
		t.Errorf("with:\n%s\nwithout:\n%s", with.Fix[FixFormatEnv], without.Fix[FixFormatEnv])
	}
}

func TestConfigReportLimitsMatchTheWire(t *testing.T) {
	if sensordom.MaxConfigReportBytes != protov2.MaxConfigReportBytes {
		t.Fatalf("domain %d, wire %d", sensordom.MaxConfigReportBytes, protov2.MaxConfigReportBytes)
	}
}

func TestSortConfigChecks(t *testing.T) {
	mk := func(id, status string) ConfigCheckView {
		c := sensordom.ConfigCheck{ID: id, Status: status}
		return ConfigCheckView{Check: c, Explanation: ExplainCheck(c)}
	}
	checks := []ConfigCheckView{
		mk("tool.a.binary", "pass"), mk("policy.local", "warn"), mk("tool.b.binary", "fail"),
		mk("platform.tls", "fail"), mk("identity.key_renewal", "skip"), mk("runtime.command_poller", "error"),
	}
	sortConfigChecks(checks)
	var got []string
	for _, c := range checks {
		got = append(got, c.Check.ID)
	}
	want := []string{"platform.tls", "tool.b.binary", "runtime.command_poller", "policy.local", "identity.key_renewal", "tool.a.binary"}
	if !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

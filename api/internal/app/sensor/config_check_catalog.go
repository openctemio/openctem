package sensor

// The platform-owned remediation catalog of sensor config checks
// (research/26 owner decision F12; pkg/domain/sensor/config_report.go).
//
// A sensor reports check ids, codes and typed parameters, never wording or
// instructions. Everything a person reads as "why" or "fix" comes from this
// table, keyed by (check id, code). Parameters from the sanitized report are
// inserted as plain text into the why, and escaped per format into the fix
// snippets: shell-quoted for env (POSIX shell lines), YAML-quoted for
// compose and helm (the helpers the install templates use). A sensor can
// add neither text, links nor commands.

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// Fix snippet formats.
const (
	FixFormatEnv     = "env"
	FixFormatCompose = "compose"
	FixFormatHelm    = "helm"
)

// ConfigCheckGroups are the closed set of check groups, in display order.
var ConfigCheckGroups = []string{"platform", "identity", "policy", "tools", "content", "network", "storage", "runtime", "config", "connector"}

// configCheckDocsBase is the docs page that explains every check: the
// "Setup check reference" of the sensor troubleshooting page (openctemio/docs
// sensors/troubleshooting.md). Each entry's Docs is a full URL on it, written
// out so scripts/check_docs_links.py can check the anchor exists.
const configCheckDocsBase = "https://docs.openctem.io/sensors/troubleshooting/"

// checkCatalogEntry explains one (id, code). ID may hold one "*" segment
// (tool.*.binary); its value is offered to the templates as the "tool"
// parameter when the check does not carry one.
type checkCatalogEntry struct {
	ID    string
	Code  string
	Group string
	Title string
	// Why is plain text; {param} is replaced by the parameter's text.
	Why string
	// Fix maps a format to a text/template; .param is the parameter
	// escaped for that format, and joinq "prefix" "param" "suffix" escapes
	// the whole concatenation (a YAML list item like "state:/path"). A
	// format whose template names a parameter the check lacks is left out.
	Fix map[string]string
	// Docs is the URL of the entry's anchor on the configCheckDocsBase page.
	Docs string
}

// Fix snippets shared by several entries.
const (
	stateEnvFix = `# Keep the sensor state on a volume that survives the container:
docker volume create openctem-sensor-state
# docker run ... -v openctem-sensor-state:{{.path}} ...
export SENSOR_STATE_DIR={{.path}}`
	stateComposeFix = `services:
  sensor:
    volumes:
      - {{joinq "state:" "path" ""}}
volumes:
  state:`
	stateHelmFix = `sensor:
  state:
    persistence:
      enabled: true`
	toolsEnvFix = `# List the scanners the sensor offers (installed in its image):
export SENSOR_TOOLS=nuclei`
	toolsComposeFix = `services:
  sensor:
    environment:
      SENSOR_TOOLS: "nuclei"`
	toolsHelmFix = `sensor:
  tools: "nuclei"`
	imageComposeFix = `# Pull the current default image (semgrep, betterleaks, trivy, nuclei):
services:
  sensor:
    image: ghcr.io/openctemio/sensor:latest`
	imageHelmFix = `sensor:
  image:
    repository: ghcr.io/openctemio/sensor
    tag: "latest"`
)

// configCheckCatalog covers every check id and code sdk-go and the sensor
// emit (research/26 §3 catalog v0). config_check_catalog_test.go fails when
// one is missing.
var configCheckCatalog = []checkCatalogEntry{
	// --- tools ---------------------------------------------------------------
	{ID: "tool.*.binary", Code: "ok", Group: "tools", Title: "Scanner {tool} is installed",
		Why: "The sensor found {tool} and it starts.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#tool-binary"},
	{ID: "tool.*.binary", Code: "not_installed", Group: "tools", Title: "Scanner {tool} is not installed",
		Why:  "The sensor offers {tool}, but its image does not contain it. The platform sends it no {tool} jobs.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#tool-binary",
		Fix: map[string]string{
			FixFormatEnv: `# Use an image that ships {{.tool}}, or stop offering it:
export SENSOR_TOOLS=nuclei`,
			FixFormatCompose: imageComposeFix,
			FixFormatHelm:    imageHelmFix,
		}},
	{ID: "tool.*.binary", Code: "broken", Group: "tools", Title: "Scanner {tool} is installed but does not start",
		Why:  "Running {tool} to check its version failed (exit code {exit_code}). Jobs for it would fail; the output below is what it printed.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#tool-binary",
		Fix: map[string]string{
			FixFormatEnv: `# Pull a fresh image; if it still fails, stop offering the scanner:
docker pull ghcr.io/openctemio/sensor:latest`,
			FixFormatCompose: imageComposeFix,
			FixFormatHelm:    imageHelmFix,
		}},
	{ID: "tool.*.binary", Code: "check_error", Group: "tools", Title: "Scanner {tool} could not be checked",
		Why: "The sensor could not run its check of {tool}. The output below says why.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#tool-binary"},
	{ID: "tool.*.selection", Code: "not_selected", Group: "tools", Title: "Scanner {tool} is not offered",
		Why:  "{tool} is installed but not listed in SENSOR_TOOLS, so the sensor does not offer it.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#tool-selection",
		Fix: map[string]string{
			FixFormatEnv:     "# Add the scanner to the list the sensor offers:\nexport SENSOR_TOOLS=nuclei,{{.tool}}",
			FixFormatCompose: "services:\n  sensor:\n    environment:\n      SENSOR_TOOLS: {{.tool}}",
			FixFormatHelm:    "sensor:\n  tools: {{.tool}}",
		}},
	{ID: "tool.*.selection", Code: "policy_excluded", Group: "tools", Title: "Scanner {tool} is excluded by the local policy",
		Why:  "The sensor's local policy does not allow {tool}, so the sensor does not offer it. Only the network owner can change the policy on the sensor host.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#tool-selection"},
	{ID: "tool.*.registration", Code: "register_failed", Group: "tools", Title: "Scanner {tool} could not be registered",
		Why:  "The sensor found {tool} but could not register it, so it is not offered. The summary below is the sensor's message.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#tool-registration"},
	{ID: "tools.available", Code: "ok", Group: "tools", Title: "Scanners are available",
		Why: "The sensor offers {count} scanner(s).", Docs: "https://docs.openctem.io/sensors/troubleshooting/#tools-available"},
	{ID: "tools.available", Code: "none", Group: "tools", Title: "No scanner is available",
		Why:  "No scanner is both installed and allowed on this sensor, so the platform cannot send it any scan.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#tools-available",
		Fix:  map[string]string{FixFormatEnv: toolsEnvFix, FixFormatCompose: toolsComposeFix, FixFormatHelm: toolsHelmFix}},

	// --- identity ------------------------------------------------------------
	{ID: "identity.state_persistent", Code: "persistent", Group: "identity", Title: "Sensor state is kept",
		Why: "The state directory {path} is on a mounted volume.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-state-persistent"},
	{ID: "identity.state_persistent", Code: "not_persistent", Group: "identity", Title: "Key renewal will break after the first rotation",
		Why:  "The sensor keeps its renewed API key in {path}, which is not on a mounted volume. Recreating the container loses it, and the sensor starts again with a retired key.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-state-persistent",
		Fix:  map[string]string{FixFormatEnv: stateEnvFix, FixFormatCompose: stateComposeFix, FixFormatHelm: stateHelmFix}},
	{ID: "identity.state_persistent", Code: "unknown", Group: "identity", Title: "Sensor state may not be kept",
		Why:  "The sensor could not tell whether {path} is on a mounted volume. If it is not, a recreated container starts with a retired key.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-state-persistent",
		Fix:  map[string]string{FixFormatEnv: stateEnvFix, FixFormatCompose: stateComposeFix, FixFormatHelm: stateHelmFix}},
	{ID: "identity.key_renewal", Code: "enabled", Group: "identity", Title: "API key renewal is on",
		Why: "The sensor renews its API key before it expires.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-key-renewal"},
	{ID: "identity.key_renewal", Code: "disabled", Group: "identity", Title: "API key renewal is off",
		Why: "Key renewal is switched off in the sensor's settings. Rotate the key yourself before it expires.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-key-renewal"},
	{ID: "identity.key_renewal", Code: "off_not_persistent", Group: "identity", Title: "API key renewal is off because the state is not kept",
		Why:  "The sensor turned key renewal off because its state directory is not on a mounted volume: a renewed key would be lost. Mount a volume to turn renewal on.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-key-renewal",
		Fix: map[string]string{
			FixFormatEnv:     "# Mount a state volume (see the state check), then:\nexport PLATFORM_KEY_AUTORENEW=true",
			FixFormatCompose: "services:\n  sensor:\n    environment:\n      PLATFORM_KEY_AUTORENEW: \"true\"\n    volumes:\n      - state:/var/lib/openctem/state\nvolumes:\n  state:",
			FixFormatHelm:    "sensor:\n  keyAutoRenew: \"true\"\n  state:\n    persistence:\n      enabled: true",
		}},
	{ID: "identity.key_renewal", Code: "start_failed", Group: "identity", Title: "API key renewal did not start",
		Why:  "The sensor could not start key renewal. The summary below is the sensor's message; the key will expire unless it is rotated.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-key-renewal"},

	// --- network -------------------------------------------------------------
	{ID: "network.scan_proxy_inherit", Code: "direct", Group: "network", Title: "Scanners connect directly",
		Why: "Scanners do not use the host's proxy settings.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#network-scan-proxy"},
	{ID: "network.scan_proxy_inherit", Code: "inherit_explicit", Group: "network", Title: "Scanners use the host proxy on purpose",
		Why: "SENSOR_SCAN_PROXY says scanners use the host's proxy settings.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#network-scan-proxy"},
	{ID: "network.scan_proxy_inherit", Code: "inherits_proxy", Group: "network", Title: "Scanners send targets through the host proxy",
		Why:  "The host sets {vars}, and scanners inherit them: scan traffic goes through that proxy, which may block it or see every target. Say which you want.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#network-scan-proxy",
		Fix: map[string]string{
			FixFormatEnv:     "# Scanners connect directly (the platform connection keeps the proxy):\nexport SENSOR_SCAN_PROXY=direct",
			FixFormatCompose: "services:\n  sensor:\n    environment:\n      SENSOR_SCAN_PROXY: \"direct\"",
			FixFormatHelm:    "sensor:\n  extraEnv:\n    - name: SENSOR_SCAN_PROXY\n      value: \"direct\"",
		}},

	// --- runtime -------------------------------------------------------------
	{ID: "runtime.oom_protect", Code: "protected", Group: "runtime", Title: "The sensor is protected from the OOM killer",
		Why: "Under memory pressure the kernel stops a scanner before the sensor.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-oom-protect"},
	{ID: "runtime.oom_protect", Code: "not_requested", Group: "runtime", Title: "OOM protection is not requested",
		Why: "The sensor does not ask the kernel to spare it under memory pressure.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-oom-protect"},
	{ID: "runtime.oom_protect", Code: "unsupported", Group: "runtime", Title: "OOM protection is not supported here",
		Why: "This host does not let the sensor ask the kernel to spare it under memory pressure.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-oom-protect"},
	{ID: "runtime.oom_protect", Code: "no_permission", Group: "runtime", Title: "OOM protection needs a capability",
		Why:  "The sensor asked the kernel to stop a scanner before itself under memory pressure, but lacks the SYS_RESOURCE capability.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-oom-protect",
		Fix: map[string]string{
			FixFormatEnv:     "# docker run ... --cap-add SYS_RESOURCE ...",
			FixFormatCompose: "services:\n  sensor:\n    cap_add: [SYS_RESOURCE]",
			FixFormatHelm:    "sensor:\n  securityContext:\n    capabilities:\n      drop: [ALL]\n      add: [SYS_RESOURCE]",
		}},
	{ID: "runtime.oom_protect", Code: "failed", Group: "runtime", Title: "OOM protection failed",
		Why: "The sensor could not set its OOM protection. The summary below is the sensor's message.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-oom-protect"},
	{ID: "runtime.command_poller", Code: "running", Group: "runtime", Title: "The sensor takes jobs",
		Why: "The sensor is polling the platform for jobs.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-command-poller"},
	{ID: "runtime.command_poller", Code: "stopped", Group: "runtime", Title: "The sensor stopped taking jobs",
		Why:  "The loop that fetches jobs from the platform stopped with an error, so the sensor runs nothing. Restart the sensor; the summary below is its message.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-command-poller"},

	// --- config --------------------------------------------------------------
	{ID: "config.alias_deprecated", Code: "legacy_name", Group: "config", Title: "Setting {name} has a new name",
		Why:  "{name} still works but is deprecated. Use {replacement} instead.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#config-alias-deprecated",
		Fix: map[string]string{
			FixFormatEnv:     "# Rename the setting: {{.name}} -> {{.replacement}}\nunset {{.name}}",
			FixFormatCompose: "# In services.sensor.environment, rename {{.name}} to {{.replacement}}",
			FixFormatHelm:    "# In sensor.extraEnv, rename {{.name}} to {{.replacement}}",
		}},
	{ID: "config.env_unknown", Code: "unknown", Group: "config", Title: "Unknown setting {name}",
		Why:  "The sensor does not read {name}, so it has no effect. Check the spelling.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#config-env-unknown",
		Fix: map[string]string{
			FixFormatEnv:     "{{with index . \"suggestion\"}}# Did you mean {{.}}?\n{{end}}unset {{.name}}",
			FixFormatCompose: "# Remove {{.name}} from services.sensor.environment{{with index . \"suggestion\"}} (did you mean {{.}}?){{end}}",
			FixFormatHelm:    "# Remove {{.name}} from sensor.extraEnv{{with index . \"suggestion\"}} (did you mean {{.}}?){{end}}",
		}},
	{ID: "config.file_unknown_key", Code: "unknown_key", Group: "config", Title: "Unknown key {key} in the config file",
		Why:  "The sensor does not know the key {key} in {path}, so it is ignored. Check the spelling.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#config-file-unknown-key",
		Fix: map[string]string{
			FixFormatEnv: "# Edit {{.path}}: remove or rename the key {{.key}}{{with index . \"suggestion\"}} (did you mean {{.}}?){{end}}",
		}},
	{ID: "config.file_unset_var", Code: "unset_var", Group: "config", Title: "Config file uses unset variable {name}",
		Why:  "{path} refers to the environment variable {name}, which is not set, so the value became empty.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#config-file-unset-var",
		Fix: map[string]string{
			FixFormatEnv: "# Set {{.name}} in the sensor's environment, or remove it from {{.path}}",
		}},
	{ID: "config.commands_disabled", Code: "daemon_without_commands", Group: "config", Title: "The sensor runs as a daemon but takes no jobs",
		Why:  "The sensor was started with -daemon but without -enable-commands, so it heartbeats but never runs a job from the platform.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#config-commands-disabled",
		Fix: map[string]string{
			FixFormatEnv:     "# Start the sensor with both flags:\n# openctemio-sensor -daemon -enable-commands",
			FixFormatCompose: "services:\n  sensor:\n    command: [\"-daemon\", \"-enable-commands\"]",
			FixFormatHelm:    "sensor:\n  mode: daemon",
		}},
	{ID: "config.tool_retired", Code: "retired_name", Group: "config", Title: "Scanner name {name} is retired",
		Why:  "{name} was replaced by {replacement}; the sensor runs {replacement} for it. Update the tool list.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#config-tool-retired",
		Fix: map[string]string{
			FixFormatEnv:     "# In SENSOR_TOOLS, replace {{.name}} with {{.replacement}}",
			FixFormatCompose: "# In services.sensor.environment.SENSOR_TOOLS, replace {{.name}} with {{.replacement}}",
			FixFormatHelm:    "# In sensor.tools, replace {{.name}} with {{.replacement}}",
		}},

	// --- platform ------------------------------------------------------------
	{ID: "platform.tls", Code: "ok", Group: "platform", Title: "TLS trust is readable",
		Why: "The certificate settings the sensor uses to trust the platform are readable.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#platform-tls"},
	{ID: "platform.tls", Code: "ca_file_unreadable", Group: "platform", Title: "The CA file in {name} cannot be read",
		Why:  "{name} points at {path}, which the sensor cannot read. TLS connections to the platform then fail with an unknown-authority error.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#platform-tls",
		Fix: map[string]string{
			FixFormatEnv:     "# Mount the platform CA certificate read-only at the path the setting names:\n# docker run ... -v \"$PWD/platform-ca.pem\":{{.path}}:ro ...\nls -l {{.path}}",
			FixFormatCompose: "services:\n  sensor:\n    volumes:\n      - {{joinq \"./platform-ca.pem:\" \"path\" \":ro\"}}",
			FixFormatHelm:    "sensor:\n  extraVolumes:\n    - name: platform-ca\n      configMap:\n        name: platform-ca\n  extraVolumeMounts:\n    - name: platform-ca\n      mountPath: {{.path}}\n      subPath: platform-ca.pem\n      readOnly: true",
		}},
	{ID: "platform.tls", Code: "ca_dir_unreadable", Group: "platform", Title: "The CA directory in {name} cannot be read",
		Why:  "{name} points at {path}, which the sensor cannot read. TLS connections to the platform then fail with an unknown-authority error.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#platform-tls",
		Fix: map[string]string{
			FixFormatEnv:     "# Mount the directory with the platform CA certificate read-only:\n# docker run ... -v \"$PWD/certs\":{{.path}}:ro ...\nls -ld {{.path}}",
			FixFormatCompose: "services:\n  sensor:\n    volumes:\n      - {{joinq \"./certs:\" \"path\" \":ro\"}}",
			FixFormatHelm:    "sensor:\n  extraVolumes:\n    - name: platform-ca\n      configMap:\n        name: platform-ca\n  extraVolumeMounts:\n    - name: platform-ca\n      mountPath: {{.path}}\n      readOnly: true",
		}},

	// --- policy --------------------------------------------------------------
	{ID: "policy.local", Code: "enforced", Group: "policy", Title: "A local policy is enforced",
		Why: "The network owner's local policy is loaded and every job is checked against it.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#policy-local"},
	{ID: "policy.local", Code: "absent", Group: "policy", Title: "No local policy",
		Why:  "No local policy is installed on the sensor host, so the sensor accepts any target outside its built-in deny list. The network owner should install one.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#policy-local",
		Fix: map[string]string{
			FixFormatEnv:     "# Install the policy read-only (owner root), then:\nexport SENSOR_LOCAL_POLICY=/etc/openctem/policy/sensor-policy.yaml",
			FixFormatCompose: "services:\n  sensor:\n    environment:\n      SENSOR_LOCAL_POLICY: \"/etc/openctem/policy/sensor-policy.yaml\"\n    volumes:\n      - ./policy:/etc/openctem/policy:ro",
			FixFormatHelm:    "sensor:\n  localPolicy:\n    enabled: true",
		}},
	{ID: "policy.template_keys", Code: "ok", Group: "policy", Title: "Template signing keys are set",
		Why: "The sensor can verify custom templates the platform signs.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#policy-template-keys"},
	{ID: "policy.template_keys", Code: "not_needed", Group: "policy", Title: "Template signing keys are not needed",
		Why: "The local policy does not allow custom templates.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#policy-template-keys"},
	{ID: "policy.template_keys", Code: "missing", Group: "policy", Title: "Custom templates are allowed but cannot be verified",
		Why:  "The local policy allows custom templates, but SENSOR_TEMPLATE_SIGNING_KEYS is not set, so the sensor refuses every custom template.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#policy-template-keys",
		Fix: map[string]string{
			FixFormatEnv:     "# The tenant's template signing public key (Settings > Sensors):\nexport SENSOR_TEMPLATE_SIGNING_KEYS='<public key>'",
			FixFormatCompose: "services:\n  sensor:\n    environment:\n      SENSOR_TEMPLATE_SIGNING_KEYS: \"<public key>\"",
			FixFormatHelm:    "sensor:\n  extraEnv:\n    - name: SENSOR_TEMPLATE_SIGNING_KEYS\n      value: \"<public key>\"",
		}},
}

type compiledCheck struct {
	entry checkCatalogEntry
	match *regexp.Regexp
	fix   map[string]*template.Template
}

var compiledCatalog = compileCheckCatalog(configCheckCatalog)

func compileCheckCatalog(entries []checkCatalogEntry) []compiledCheck {
	out := make([]compiledCheck, 0, len(entries))
	for _, e := range entries {
		pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(e.ID), `\*`, `([a-z0-9_-]+)`) + "$"
		c := compiledCheck{entry: e, match: regexp.MustCompile(pattern), fix: map[string]*template.Template{}}
		for format, src := range e.Fix {
			c.fix[format] = template.Must(template.New(e.ID + "/" + e.Code + "/" + format).
				Option("missingkey=error").Funcs(template.FuncMap{"joinq": joinqUnbound}).Parse(src))
		}
		out = append(out, c)
	}
	return out
}

// lookupCheck returns the catalog entry of (id, code) and the wildcard
// value of its id ("" without one).
func lookupCheck(id, code string) (*compiledCheck, string) {
	for i := range compiledCatalog {
		c := &compiledCatalog[i]
		if c.entry.Code != code {
			continue
		}
		if m := c.match.FindStringSubmatch(id); m != nil {
			wild := ""
			if len(m) > 1 {
				wild = m[1]
			}
			return c, wild
		}
	}
	return nil, ""
}

// CheckExplanation is the catalog's text for one check.
type CheckExplanation struct {
	Known   bool
	Group   string
	Title   string
	Why     string
	Fix     map[string]string
	DocsURL string
}

var whyParamRE = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)

// ExplainCheck explains a sanitized check from the catalog: the title and
// why with its parameters as plain text, and the fix snippets with its
// parameters escaped per format. An unknown (id, code) is not explained:
// the title is the id and nothing else is set.
func ExplainCheck(c sensordom.ConfigCheck) CheckExplanation {
	entry, wild := lookupCheck(c.ID, c.Code)
	if entry == nil {
		return CheckExplanation{Group: checkGroupOf(c.ID), Title: c.ID, Fix: map[string]string{}}
	}
	text := map[string]string{}
	for k, p := range c.Params {
		text[k] = p.Text()
	}
	if _, ok := text["tool"]; !ok && wild != "" {
		text["tool"] = wild
	}
	plain := func(s string) string {
		return whyParamRE.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := text[m[1:len(m)-1]]; ok && v != "" {
				return v
			}
			return "(not reported)"
		})
	}
	out := CheckExplanation{Known: true, Group: entry.entry.Group, Title: plain(entry.entry.Title),
		Why: plain(entry.entry.Why), Fix: map[string]string{}, DocsURL: entry.entry.Docs}
	for format, tmpl := range entry.fix {
		if s, ok := renderFix(tmpl, format, text); ok {
			out.Fix[format] = s
		}
	}
	return out
}

// renderFix renders one snippet with every parameter escaped for format;
// false when the template needs a parameter the check does not carry.
func renderFix(t *template.Template, format string, params map[string]string) (string, bool) {
	escape := yamlQuote
	if format == FixFormatEnv {
		escape = shellQuote
	}
	data := make(map[string]string, len(params))
	for k, v := range params {
		// A shell-quoted value may sit in a comment line, where a line
		// break would end the comment: refuse control characters (the
		// sanitizer already does; this does not depend on it).
		if format == FixFormatEnv && strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return "", false
		}
		data[k] = escape(v)
	}
	joinq := func(prefix, key, suffix string) (string, error) {
		v, ok := params[key]
		if !ok {
			return "", fmt.Errorf("parameter %s not reported", key)
		}
		return escape(prefix + v + suffix), nil
	}
	tc, err := t.Clone()
	if err != nil {
		return "", false
	}
	var b strings.Builder
	if err := tc.Funcs(template.FuncMap{"joinq": joinq}).Execute(&b, data); err != nil {
		return "", false
	}
	return b.String(), true
}

// joinqUnbound is the parse-time stand-in of joinq (renderFix binds the
// real one to the check's parameters).
func joinqUnbound(_, _, _ string) (string, error) {
	return "", errors.New("joinq is not bound")
}

// checkGroupOf is the group of a check id: its first segment when that is
// a group ("tool" and "tools" are tools), else config.
func checkGroupOf(id string) string {
	first, _, _ := strings.Cut(id, ".")
	if first == "tool" {
		return "tools"
	}
	for _, g := range ConfigCheckGroups {
		if g == first {
			return g
		}
	}
	return "config"
}

// catalogKeys lists the (id, code) pairs of the catalog, for tests.
func catalogKeys() []string {
	out := make([]string, 0, len(configCheckCatalog))
	for _, e := range configCheckCatalog {
		out = append(out, e.ID+" "+e.Code)
	}
	sort.Strings(out)
	return out
}

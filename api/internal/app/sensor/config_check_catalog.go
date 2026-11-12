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

	"github.com/openctemio/openctem/api/pkg/brand"
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
// sandboxDocs is the troubleshooting anchor of the network-confinement
// check.
// checkSandboxUnconfined is the check of tools run without the sandbox.
const checkSandboxUnconfined = "runtime.sandbox_unconfined"

const sandboxDocs = "https://docs.openctem.io/sensors/troubleshooting/#runtime-sandbox-network"

// The control channel's DNS (sdk-go httpsec last-known-good addresses).
const (
	controlDNSDocs    = "https://docs.openctem.io/sensors/troubleshooting/#runtime-control-dns"
	coreAddressesDocs = "https://docs.openctem.io/sensors/troubleshooting/#network-core-addresses"
)

// controlDNSFix pins the platform host so the control channel needs no DNS
// (the chart has no host alias value: on Kubernetes add a hostAliases entry
// to the pod spec, see the docs).
var controlDNSFix = map[string]string{
	FixFormatEnv: `# Pin the platform host on the sensor host (replace the address):
echo "<platform address> "{{.host}} | sudo tee -a /etc/hosts`,
	FixFormatCompose: `services:
  sensor:
    # Pin the platform host (replace the address); keep the DNS servers,
    # gateways, the platform and this host out of intrusive scans.
    extra_hosts:
      - {{joinq "" "host" ":<platform address>"}}`,
}

// sandboxSeccompFix runs the sensor under its own seccomp profile, which the
// platform serves at /api/v1/sensors/install/seccomp-profile.
var sandboxSeccompFix = map[string]string{
	FixFormatEnv: `# Download the sensor's seccomp profile (served by the platform; the
# install commands check its SHA-256) and run the container with it:
# docker run ... --security-opt seccomp=/etc/openctem/sensor-seccomp.json ...`,
	FixFormatCompose: `services:
  sensor:
    security_opt:
      - no-new-privileges:true
      - seccomp=./sensor-seccomp.json`,
	FixFormatHelm: `sensor:
  sandbox:
    seccompProfile: openctem`,
}

const (
	// The templates mount one data volume at /var/lib/openctem (state/,
	// outbox/, content/); a volume on the reported directory itself works
	// for any layout, so the env and compose fixes mount that.
	stateEnvFix = `# Keep the sensor state on a volume that survives the container
# (the install snippets mount one data volume at /var/lib/openctem):
docker volume create openctem-sensor-data
# docker run ... -v openctem-sensor-data:/var/lib/openctem ...
# or a volume on the state directory itself:
export SENSOR_STATE_DIR={{.path}}`
	stateComposeFix = `# Recommended: one data volume at /var/lib/openctem (state/, outbox/,
# content/). A volume on the state directory itself works too:
services:
  sensor:
    volumes:
      - {{joinq "state:" "path" ""}}
volumes:
  state:`
	dataHelmFix = `sensor:
  data:
    persistence:
      enabled: true`
	outboxEnvFix = `# Keep the outbox on a volume that survives the container
# (the install snippets mount one data volume at /var/lib/openctem):
docker volume create openctem-sensor-data
# docker run ... -v openctem-sensor-data:/var/lib/openctem ...
# or a volume on the outbox directory itself:
export SENSOR_OUTBOX_DIR={{.path}}`
	outboxComposeFix = `# Recommended: one data volume at /var/lib/openctem (state/, outbox/,
# content/). A volume on the outbox directory itself works too:
services:
  sensor:
    volumes:
      - {{joinq "outbox:" "path" ""}}
volumes:
  outbox:`
	// The sensor offers every tool its image ships; a tool list only narrows
	// that set, so the fix is an image that ships the scanner and a local
	// policy (tools.allow) that allows it.
	toolsEnvFix = `# Use an image that ships the scanners (the default one carries semgrep,
# betterleaks, trivy and nuclei) and check tools.allow in the local policy.
# Remove SENSOR_TOOLS if it is set: the sensor then offers what it finds.
docker pull ghcr.io/openctemio/sensor:latest`
	toolsComposeFix = `# Use an image that ships the scanners, check tools.allow in the local
# policy, and drop SENSOR_TOOLS from the environment if it is set:
services:
  sensor:
    image: ghcr.io/openctemio/sensor:latest`
	toolsHelmFix = `# Use an image that ships the scanners and leave sensor.tools empty:
sensor:
  image:
    repository: ghcr.io/openctemio/sensor
    tag: "latest"
  tools: ""`
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
			FixFormatEnv: `# Use an image that ships {{.tool}}:
docker pull ghcr.io/openctemio/sensor:latest`,
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
		Why:  "{tool} is installed but left out by the sensor's SENSOR_TOOLS (or -tools) setting, so the sensor does not offer it.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#tool-selection",
		Fix: map[string]string{
			FixFormatEnv:     "# Remove SENSOR_TOOLS (and -tools): the sensor then offers every tool it finds.\n# Narrow the set in the local policy's tools.allow instead.\nunset SENSOR_TOOLS",
			FixFormatCompose: "# Drop SENSOR_TOOLS from services.sensor.environment; narrow the set in the\n# local policy's tools.allow instead.",
			FixFormatHelm:    "sensor:\n  tools: \"\"",
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
		Fix:  map[string]string{FixFormatEnv: stateEnvFix, FixFormatCompose: stateComposeFix, FixFormatHelm: dataHelmFix}},
	{ID: "identity.state_persistent", Code: "unknown", Group: "identity", Title: "Sensor state may not be kept",
		Why:  "The sensor could not tell whether {path} is on a mounted volume. If it is not, a recreated container starts with a retired key.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-state-persistent",
		Fix:  map[string]string{FixFormatEnv: stateEnvFix, FixFormatCompose: stateComposeFix, FixFormatHelm: dataHelmFix}},
	{ID: "identity.key_renewal", Code: "enabled", Group: "identity", Title: "API key renewal is on",
		Why: "The sensor renews its API key before it expires.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-key-renewal"},
	{ID: "identity.key_renewal", Code: "disabled", Group: "identity", Title: "API key renewal is off",
		Why: "Key renewal is switched off in the sensor's settings. Rotate the key yourself before it expires.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-key-renewal"},
	{ID: "identity.key_renewal", Code: "off_not_persistent", Group: "identity", Title: "API key renewal is off because the state is not kept",
		Why:  "The sensor turned key renewal off because its state directory is not on a mounted volume: a renewed key would be lost. Mount a volume to turn renewal on.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-key-renewal",
		Fix: map[string]string{
			FixFormatEnv:     "# Mount a state volume (see the state check), then:\nexport SENSOR_KEY_AUTORENEW=true",
			FixFormatCompose: "services:\n  sensor:\n    environment:\n      SENSOR_KEY_AUTORENEW: \"true\"\n    volumes:\n      - data:/var/lib/openctem\nvolumes:\n  data:",
			FixFormatHelm:    "sensor:\n  keyAutoRenew: \"true\"\n  data:\n    persistence:\n      enabled: true",
		}},
	{ID: "identity.key_renewal", Code: "start_failed", Group: "identity", Title: "API key renewal did not start",
		Why:  "The sensor could not start key renewal. The summary below is the sensor's message; the key will expire unless it is rotated.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#identity-key-renewal"},

	// --- storage -------------------------------------------------------------
	{ID: "storage.outbox_persistent", Code: "persistent", Group: "storage", Title: "Undelivered results are kept",
		Why: "The outbox {path} is on a mounted volume.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#storage-outbox-persistent"},
	{ID: "storage.outbox_persistent", Code: "not_persistent", Group: "storage", Title: "Undelivered results are lost when the container is recreated",
		Why:  "The sensor keeps results the platform has not accepted yet in {path}, which is not on a mounted volume. Recreating the container during an outage loses them.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#storage-outbox-persistent",
		Fix:  map[string]string{FixFormatEnv: outboxEnvFix, FixFormatCompose: outboxComposeFix, FixFormatHelm: dataHelmFix}},
	{ID: "storage.outbox_persistent", Code: "unknown", Group: "storage", Title: "Undelivered results may not be kept",
		Why:  "The sensor could not tell whether {path} is on a mounted volume. If it is not, a recreated container loses results the platform has not accepted yet.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#storage-outbox-persistent",
		Fix:  map[string]string{FixFormatEnv: outboxEnvFix, FixFormatCompose: outboxComposeFix, FixFormatHelm: dataHelmFix}},

	// --- network -------------------------------------------------------------
	{ID: CoreAddressesCheckID, Code: "listed", Group: "network", Title: "Core infrastructure this sensor depends on",
		Why:  "The sensor's DNS resolvers, gateways, its own address and the platform's addresses. An intrusive scan that covers them can cut the sensor off its platform (an IPS block or a resolver knocked over): new scans warn when their targets include them.",
		Docs: coreAddressesDocs},
	{ID: CoreAddressesCheckID, Code: "not_reported", Group: "network", Title: "Core infrastructure addresses are not reported",
		Why: "SENSOR_NETWORK_REPORT=off: the sensor names none of its resolvers, gateways or addresses, so scans cannot warn when they target them.", Docs: coreAddressesDocs},
	{ID: CoreAddressesCheckID, Code: "none_known", Group: "network", Title: "No core infrastructure address known yet",
		Why: "The sensor has not detected its resolvers, gateways or the platform's addresses yet, or the local policy does not let it scan them.", Docs: coreAddressesDocs},
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
	{ID: "runtime.task_root_memory", Code: "in_memory", Group: "runtime", Title: "Task files stay in memory",
		Why: "The directory where tools write files for a run (with the keys a task received) is in memory: they never reach a disk.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-task-root-memory"},
	{ID: "runtime.task_root_memory", Code: "on_disk", Group: "runtime", Title: "Task files are written to disk",
		Why: "The directory where tools write files for a run is on disk: a file with the keys a task received stays on the disk until the task ends. Mount a tmpfs there, or point TMPDIR at one.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-task-root-memory"},
	{ID: "runtime.command_poller", Code: "running", Group: "runtime", Title: "The sensor takes jobs",
		Why: "The sensor is polling the platform for jobs.", Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-command-poller"},
	{ID: "runtime.command_poller", Code: "stopped", Group: "runtime", Title: "The sensor stopped taking jobs",
		Why:  "The loop that fetches jobs from the platform stopped with an error, so the sensor runs nothing. Restart the sensor; the summary below is its message.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#runtime-command-poller"},

	{ID: ControlDNSCheckID, Code: "resolving", Group: "runtime", Title: "The platform host name resolves",
		Why: "The sensor looks up {host} and reaches the platform at the address it gets.", Docs: controlDNSDocs},
	{ID: ControlDNSCheckID, Code: "address_literal", Group: "runtime", Title: "The platform URL is an IP address",
		Why: "The sensor reaches the platform without a DNS lookup.", Docs: controlDNSDocs},
	{ID: ControlDNSCheckID, Code: "via_proxy", Group: "runtime", Title: "The proxy resolves the platform host",
		Why: "Platform requests go through a proxy, which looks up the platform host itself: the sensor's resolver is not on the control path.", Docs: controlDNSDocs},
	{ID: ControlDNSCheckID, Code: "plain_http", Group: "runtime", Title: "No DNS fallback over plain HTTP",
		Why: "The platform URL is plain HTTP, so the sensor never dials a cached platform address: only a TLS connection proves the address still belongs to the platform. Use an https URL.", Docs: controlDNSDocs},
	{ID: ControlDNSCheckID, Code: "cached_address", Group: "runtime", Title: "The platform host name does not resolve",
		Why:  "Lookups of {host} fail ({cause}). The sensor still reaches the platform at the address it last resolved, and TLS still verifies {host}, but it stops once that address is older than SENSOR_CONTROL_DNS_MAX_STALE. Check the resolver the sensor uses, pin the platform host, and keep the DNS server out of intrusive scans.",
		Docs: controlDNSDocs, Fix: controlDNSFix},
	{ID: ControlDNSCheckID, Code: "lookup_failed", Group: "runtime", Title: "The sensor lost the platform: DNS failure",
		Why:  "Lookups of {host} fail ({cause}) and the sensor knows no recent address, so heartbeats, jobs and results stop until DNS answers; jobs it held are handed to other sensors when their lease ends. Check the resolver the sensor uses, pin the platform host, and keep the DNS server out of intrusive scans.",
		Docs: controlDNSDocs, Fix: controlDNSFix},
	{ID: ControlDNSCheckID, Code: "recovered", Group: "runtime", Title: "The platform host name failed to resolve for a while",
		Why:  "Lookups of {host} failed for a period and work again; the summary below says when. If it happened during a scan, the scan probably reached the DNS server: exclude it and the other core infrastructure from intrusive scans, or pin the platform host.",
		Docs: controlDNSDocs, Fix: controlDNSFix},

	{ID: "runtime.sandbox_network", Code: "confined", Group: "runtime", Title: "Tool runs are network-confined",
		Why: "Each tool task runs in its own network namespace and reaches only its targets, through its forwarder. The sensor can take jobs that need confinement (a web scope).", Docs: sandboxDocs},
	{ID: "runtime.sandbox_network", Code: "userns_disabled_host", Group: "runtime", Title: "Tool runs are not network-confined: the host disables user namespaces",
		Why:  "The host kernel refuses unprivileged user namespaces (kernel.unprivileged_userns_clone=0, or user.max_user_namespaces=0), so no container profile can allow them; the check's excerpt lists the values the sensor read. The host admin sets kernel.unprivileged_userns_clone=1 (or a positive user.max_user_namespaces) in /etc/sysctl.d and runs sysctl --system. Keep kernel.apparmor_restrict_unprivileged_userns=1 and the container's docker-default AppArmor profile so unconfined local processes stay restricted; never set the restriction to 0. If confinement still fails with the restriction on and docker-default applied, give the sensor container an AppArmor profile that grants userns. On a shared machine a dedicated host or VM for the sensor is the cleanest option. Until then jobs that need confinement (a web scope) go to other sensors.",
		Docs: sandboxDocs},
	{ID: "runtime.sandbox_network", Code: "userns_blocked", Group: "runtime", Title: "Tool runs are not network-confined: the container's seccomp profile blocks it",
		Why:  "The host allows user namespaces (its sysctls are not the cause) but the container runtime's seccomp profile refuses the namespaces confinement needs. Run the sensor with its own seccomp profile (the install commands download it). If it already runs with that profile, read the excerpt for the host values the sensor saw. Until then jobs that need confinement (a web scope) go to other sensors.",
		Docs: sandboxDocs, Fix: sandboxSeccompFix},
	{ID: "runtime.sandbox_network", Code: "userns_restricted", Group: "runtime", Title: "Tool runs are not network-confined: the host restricts user namespaces",
		Why:  "The host's AppArmor restriction on unprivileged user namespaces (Ubuntu 23.10 and later, kernel.apparmor_restrict_unprivileged_userns=1) applies to this process. Keep the restriction on and run the container with its default AppArmor profile (never apparmor=unconfined), or with an AppArmor profile that grants userns. Do not set the restriction to 0 host-wide.",
		Docs: sandboxDocs},
	{ID: "runtime.sandbox_network", Code: "off", Group: "runtime", Title: "Network confinement is turned off",
		Why: "SENSOR_SANDBOX_NETWORK=off: tool tasks are not confined, and jobs that need confinement (a web scope) go to other sensors. Remove the setting (the default is auto).", Docs: sandboxDocs},
	{ID: "runtime.sandbox_network", Code: "sandbox_off", Group: "runtime", Title: "The tool sandbox is turned off",
		Why: "SENSOR_SANDBOX=off: tool tasks run without the sandbox, so their network is not confined either. Remove the setting (the default is auto).", Docs: sandboxDocs},
	{ID: "runtime.sandbox_network", Code: "unavailable", Group: "runtime", Title: "Tool runs are not network-confined",
		Why:  "The sensor could not confine its tools' network; the summary below is its message. Jobs that need confinement (a web scope) go to other sensors.",
		Docs: sandboxDocs, Fix: sandboxSeccompFix},

	{ID: checkSandboxUnconfined, Code: "sandboxed", Group: "runtime", Title: "Tools run in the sandbox",
		Why: "Every tool task runs in the sensor's sandbox.", Docs: sandboxDocs},
	{ID: checkSandboxUnconfined, Code: "active_refused", Group: "runtime", Title: "Tools that contact their targets are refused: no sandbox on this host",
		Why:  "The tool sandbox is Linux only, and this sensor's host has none (macOS, Windows). Tools that contact their targets (tier T1 and above) are refused so they never run unconfined; passive lookups still run. Run the sensor on Linux (or in its container), or set SENSOR_SANDBOX=off to acknowledge running every tool unconfined.",
		Docs: sandboxDocs},
	{ID: checkSandboxUnconfined, Code: "acknowledged", Group: "runtime", Title: "Tools run unconfined (the sandbox is turned off)",
		Why: "SENSOR_SANDBOX=off: the operator acknowledged that every tool, those that contact their targets included, runs as a plain process without the sandbox. Remove the setting on a Linux host (the default is auto).", Docs: sandboxDocs},

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
		Why:  "Platform commands are turned off on this sensor (-enable-commands=false or sensor.enable_commands: false), so it heartbeats but never runs a job from the platform.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#config-commands-disabled",
		Fix: map[string]string{
			FixFormatEnv:     "# Remove -enable-commands=false from the sensor's command line\n# and sensor.enable_commands: false from its config file",
			FixFormatCompose: "# Remove -enable-commands=false from services.sensor.command\n# and sensor.enable_commands: false from the mounted config file",
			FixFormatHelm:    "sensor:\n  mode: daemon",
		}},
	{ID: "config.tool_retired", Code: "retired_name", Group: "config", Title: "Scanner name {name} is retired",
		Why:  "{name} was replaced by {replacement}; the sensor runs {replacement} for it. Update the tool list.",
		Docs: "https://docs.openctem.io/sensors/troubleshooting/#config-tool-retired",
		Fix: map[string]string{
			FixFormatEnv:     "# In SENSOR_TOOLS, replace {{.name}} with {{.replacement}} (or remove SENSOR_TOOLS)",
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
	{ID: "policy.local", Code: "required_absent", Group: "policy", Title: "A local policy is required but missing",
		Why:  "This sensor requires a local policy and none is installed, so it refuses every job with a network target, custom templates and callbacks. Install the policy from the Local policy tab of the install commands.",
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
		Why: plain(entry.entry.Why), Fix: map[string]string{}, DocsURL: brand.Instance().DocsLink(entry.entry.Docs)}
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

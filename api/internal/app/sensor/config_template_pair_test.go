package sensor

// Pairing installs (SensorTemplateData.Auth = AuthPair): the snippets the
// "Add sensor" panel shows before any sensor exists. No API key anywhere,
// the pairing code (when the console made one) and the job-signing root
// passed to the sensor, the same hardening as a key install.

import (
	"errors"
	"io"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/logger"
)

func pairData(t *testing.T, code string) SensorTemplateData {
	d := fullData(t)
	d.APIKey = ""
	d.Auth = AuthPair
	d.PairingCode = code
	d.JobSigningRoot = "root-2026a"
	d.Sensor = daemonSensor()
	d.Sensor.Name = "openctem-sensor"
	return d
}

func TestTemplates_PairInstallsCarryNoKey(t *testing.T) {
	for _, dir := range templateSources {
		for _, code := range []string{"", "K7QM-4ZTD"} {
			out := render(t, dir, pairData(t, code))
			for name, text := range map[string]string{"docker": out.Docker, "compose": out.Compose,
				"kubernetes": out.Kubernetes, "cli": out.CLI} {
				for _, bad := range []string{"SENSOR_API_KEY", "OPENCTEM_API_KEY", "octs_", "api-key"} {
					if strings.Contains(text, bad) {
						t.Errorf("[%s code=%q] %s pairing install mentions %q:\n%s", dir, code, name, bad, text)
					}
				}
				hasCode := strings.Contains(text, "SENSOR_PAIRING_CODE")
				if hasCode != (code != "") {
					t.Errorf("[%s code=%q] %s: SENSOR_PAIRING_CODE present=%v:\n%s", dir, code, name, hasCode, text)
				}
				if !strings.Contains(text, "SENSOR_JOB_SIGNING_ROOT") {
					t.Errorf("[%s] %s does not pass the job-signing root:\n%s", dir, name, text)
				}
			}
		}
	}
}

func TestTemplates_PairDockerWorksAsPasted(t *testing.T) {
	for _, dir := range templateSources {
		d := render(t, dir, pairData(t, "K7QM-4ZTD")).Docker
		bashSyntaxOK(t, dir+" pair docker", d)
		continuationLinesOK(t, dir+" pair docker", d)
		for _, want := range []string{
			"-e SENSOR_PAIRING_CODE='K7QM-4ZTD' \\",
			"-e SENSOR_JOB_SIGNING_ROOT='root-2026a' \\",
			"-e SENSOR_API_URL='https://192.0.2.204'",
			"--read-only --cap-drop ALL --security-opt no-new-privileges:true",
			"--security-opt seccomp=/etc/openctem/sensor-seccomp.json",
			"sha256sum -c -",
			"-e SENSOR_LOCAL_POLICY=/etc/openctem/sensor-policy.yaml",
			"docker logs -f openctem-sensor",
		} {
			if !strings.Contains(d, want) {
				t.Errorf("[%s] pair docker snippet lacks %q:\n%s", dir, want, d)
			}
		}
	}
}

func TestTemplates_PairLinuxServiceWorksAsPasted(t *testing.T) {
	for _, dir := range templateSources {
		c := render(t, dir, pairData(t, "K7QM-4ZTD")).CLI
		bashSyntaxOK(t, dir+" pair cli", c)
		for _, want := range []string{
			"V='v0.4.2'",
			"sha256sum -c --ignore-missing checksums.txt",
			"SENSOR_PAIRING_CODE=K7QM-4ZTD",
			"sudo chmod 0600 /etc/openctem/sensor.env",
			"NoNewPrivileges=yes",
			"ProtectSystem=strict",
			"ReadWritePaths=/var/lib/openctem",
			"sudo install -d -m 0700 -o openctem -g openctem /var/lib/openctem",
			"sudo systemctl enable --now openctem-sensor",
			"SSL_CERT_DIR=/etc/openctem/certs",
		} {
			if !strings.Contains(c, want) {
				t.Errorf("[%s] pair linux snippet lacks %q:\n%s", dir, want, c)
			}
		}
	}
}

func TestTemplates_PairComposeAndKubernetesAreValid(t *testing.T) {
	for _, dir := range templateSources {
		out := render(t, dir, pairData(t, "K7QM-4ZTD"))
		var doc struct {
			Services map[string]struct {
				Environment map[string]string `yaml:"environment"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(out.Compose), &doc); err != nil {
			t.Fatalf("[%s] compose is not YAML: %v\n%s", dir, err, out.Compose)
		}
		env := doc.Services["sensor"].Environment
		if env["SENSOR_PAIRING_CODE"] != "K7QM-4ZTD" || env["SENSOR_JOB_SIGNING_ROOT"] != "root-2026a" {
			t.Errorf("[%s] compose environment = %v", dir, env)
		}

		dec := yaml.NewDecoder(strings.NewReader(out.Kubernetes))
		var kinds []string
		for {
			var obj map[string]any
			err := dec.Decode(&obj)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("[%s] manifest is not YAML: %v\n%s", dir, err, out.Kubernetes)
			}
			if obj == nil {
				continue
			}
			kinds = append(kinds, obj["kind"].(string))
			if obj["kind"] == "Secret" {
				data, _ := obj["stringData"].(map[string]any)
				if _, ok := data["ca.crt"]; !ok || len(data) != 1 {
					t.Errorf("[%s] the pairing Secret holds only the CA: %v", dir, data)
				}
			}
		}
		if strings.Join(kinds, ",") != "Secret,PersistentVolumeClaim,Deployment" {
			t.Errorf("[%s] kinds = %v", dir, kinds)
		}
		// Without a private CA there is nothing secret at all.
		d := pairData(t, "")
		d.CACert = ""
		if k := render(t, dir, d).Kubernetes; strings.Contains(k, "kind: Secret") {
			t.Errorf("[%s] a pairing install without a CA renders a Secret:\n%s", dir, k)
		}
	}
}

func TestTemplates_PairRefusesAKeyAndUnknownAuth(t *testing.T) {
	svc := NewSensorConfigTemplateService("/nonexistent-uses-builtins", logger.NewNop())
	d := pairData(t, "")
	d.APIKey = "octs_x"
	if _, err := svc.Render(d); err == nil {
		t.Error("a pairing install with an API key rendered")
	}
	d = pairData(t, "")
	d.Auth = "bearer"
	if _, err := svc.Render(d); err == nil {
		t.Error("an unknown auth mode rendered")
	}
}

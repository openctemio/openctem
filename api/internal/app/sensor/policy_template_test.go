package sensor

import (
	"net/netip"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// policyDoc is the sensor-policy/v1 shape the template must produce (the
// sensor refuses unknown keys, so this mirrors sdk-go core.LocalPolicy).
type policyDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Targets    struct {
		Allow        []string `yaml:"allow"`
		Deny         []string `yaml:"deny"`
		AllowPrivate bool     `yaml:"allow_private"`
	} `yaml:"targets"`
	Tools *struct {
		Allow []string `yaml:"allow"`
	} `yaml:"tools"`
	AllowCustomTemplates bool   `yaml:"allow_custom_templates"`
	AllowInteractsh      bool   `yaml:"allow_interactsh"`
	KillSwitchFile       string `yaml:"kill_switch_file"`
}

func parsePolicyDoc(t *testing.T, raw string) policyDoc {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(raw))
	dec.KnownFields(true)
	var d policyDoc
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("policy template is not a sensor-policy/v1 document: %v\n%s", err, raw)
	}
	return d
}

func TestPolicyFromZones(t *testing.T) {
	sensorID, other := shared.NewID(), shared.NewID()
	zones := []*scanzone.Zone{
		{Name: "dc", Ranges: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("203.0.113.0/24")}, SensorIDs: []shared.ID{sensorID}},
		{Name: "other", Ranges: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, SensorIDs: []shared.ID{other}},
		{Name: "dup", Ranges: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, SensorIDs: []shared.ID{sensorID, other}},
		nil,
	}
	p := PolicyFromZones(zones, sensorID)
	if strings.Join(p.Ranges, ",") != "10.20.0.0/16,203.0.113.0/24" || !p.AllowPrivate || p.Open {
		t.Fatalf("%+v", p)
	}
	zones = append(zones, &scanzone.Zone{Name: "default", IsDefault: true, SensorIDs: []shared.ID{sensorID}})
	if !PolicyFromZones(zones, sensorID).Open {
		t.Fatal("a sensor in the default zone gets no allow list")
	}
	if p := PolicyFromZones(zones, shared.NewID()); len(p.Ranges) != 0 || p.Open || p.AllowPrivate {
		t.Fatalf("unassigned sensor: %+v", p)
	}
}

func TestTemplates_PolicyIsValid(t *testing.T) {
	for _, dir := range templateSources {
		data := fullData(t)
		data.Policy = PolicyTemplateData{Ranges: []string{"10.20.0.0/16", "203.0.113.0/24"}, AllowPrivate: true}
		r := render(t, dir, data)
		d := parsePolicyDoc(t, r.Policy)
		if d.APIVersion != "openctem.io/sensor-policy/v1" || strings.Join(d.Targets.Allow, ",") != "10.20.0.0/16,203.0.113.0/24" ||
			!d.Targets.AllowPrivate || d.Tools == nil || strings.Join(d.Tools.Allow, ",") != "nuclei,trivy" ||
			d.AllowCustomTemplates || d.AllowInteractsh || d.KillSwitchFile != "/etc/openctem/STOP" {
			t.Errorf("[%s] policy %+v\n%s", dir, d, r.Policy)
		}
		// Private ranges: every daemon snippet turns the private switch on too.
		for name, snippet := range map[string]string{"docker": r.Docker, "compose": r.Compose, "kubernetes": r.Kubernetes} {
			if !strings.Contains(snippet, "SENSOR_ALLOW_PRIVATE_TARGETS") {
				t.Errorf("[%s] %s snippet lacks SENSOR_ALLOW_PRIVATE_TARGETS for a private zone", dir, name)
			}
		}

		// No zone: no allow list (commented example); default zone: open.
		for _, p := range []PolicyTemplateData{{}, {Open: true, Ranges: []string{"10.0.0.0/8"}}} {
			data.Policy = p
			r := render(t, dir, data)
			d := parsePolicyDoc(t, r.Policy)
			if d.Targets.Allow != nil || d.Targets.AllowPrivate {
				t.Errorf("[%s] %+v: allow %v private %v", dir, p, d.Targets.Allow, d.Targets.AllowPrivate)
			}
			if strings.Contains(r.Docker, "SENSOR_ALLOW_PRIVATE_TARGETS") {
				t.Errorf("[%s] %+v: docker turns private targets on", dir, p)
			}
		}
	}
}

func TestTemplates_KubernetesHardened(t *testing.T) {
	for _, dir := range templateSources {
		k := render(t, dir, fullData(t)).Kubernetes
		for _, want := range []string{
			"runAsNonRoot: true", "type: RuntimeDefault", "allowPrivilegeEscalation: false",
			"readOnlyRootFilesystem: true", `drop: ["ALL"]`, "name: dmz-scanner-01-policy",
			"mountPath: /etc/openctem/policy", "value: /etc/openctem/policy/sensor-policy.yaml",
			"kubectl create configmap dmz-scanner-01-policy",
		} {
			if !strings.Contains(k, want) {
				t.Errorf("[%s] kubernetes lacks %q", dir, want)
			}
		}
		h := render(t, dir, fullData(t)).Helm
		if !strings.Contains(h, "--set sensor.localPolicy.enabled=true") || !strings.Contains(h, "--set-file sensor.localPolicy.policy=sensor-policy.yaml") {
			t.Errorf("[%s] helm does not mount the policy:\n%s", dir, h)
		}
	}
}

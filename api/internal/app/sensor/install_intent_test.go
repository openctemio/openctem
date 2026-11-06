package sensor

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestInstallIntent_Apply(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          InstallIntent
		wantPrivate bool
		wantPin     string
	}{
		{"default", InstallIntent{}, false, ""},
		{"internet", InstallIntent{Purpose: InstallPurposeInternet}, false, ""},
		{"internal", InstallIntent{Purpose: InstallPurposeInternal}, true, ""},
		{"both", InstallIntent{Purpose: InstallPurposeBoth}, true, ""},
		{"internal pinned", InstallIntent{Purpose: InstallPurposeInternal, AllowedRanges: []string{"10.0.0.0/16", " 192.168.1.0/24", "10.0.4.0/24"}},
			true, "10.0.0.0/16,192.168.1.0/24"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d SensorTemplateData
			if err := tc.in.Apply(&d); err != nil {
				t.Fatal(err)
			}
			if d.Policy.AllowPrivate != tc.wantPrivate || d.HostAllowedRanges != tc.wantPin {
				t.Fatalf("allow_private=%v pin=%q, want %v %q", d.Policy.AllowPrivate, d.HostAllowedRanges, tc.wantPrivate, tc.wantPin)
			}
			if (tc.wantPin != "") != (d.Policy.Source == PolicySourceHostPin) {
				t.Errorf("policy source = %q", d.Policy.Source)
			}
		})
	}
}

func TestInstallIntent_ApplyRefuses(t *testing.T) {
	many := make([]string, MaxInstallAllowedRanges+1)
	for i := range many {
		many[i] = "10.0.0.1"
	}
	for name, in := range map[string]InstallIntent{
		"unknown purpose":      {Purpose: "lan"},
		"pin without internal": {AllowedRanges: []string{"10.0.0.0/16"}},
		"pin with internet":    {Purpose: InstallPurposeInternet, AllowedRanges: []string{"10.0.0.0/16"}},
		"pin with both":        {Purpose: InstallPurposeBoth, AllowedRanges: []string{"10.0.0.0/16"}},
		"public range":         {Purpose: InstallPurposeInternal, AllowedRanges: []string{"203.0.113.0/24"}},
		"deny list":            {Purpose: InstallPurposeInternal, AllowedRanges: []string{"169.254.169.254"}},
		"shell metacharacters": {Purpose: InstallPurposeInternal, AllowedRanges: []string{"10.0.0.0/16'; id #"}},
		"too many":             {Purpose: InstallPurposeInternal, AllowedRanges: many},
	} {
		var d SensorTemplateData
		err := in.Apply(&d)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
		if d.Policy.AllowPrivate || d.HostAllowedRanges != "" {
			t.Errorf("%s: a refused intent still set allow_private=%v pin=%q", name, d.Policy.AllowPrivate, d.HostAllowedRanges)
		}
	}
}

// The private switch reaches every install command only when the person
// said the sensor scans internal networks, with the comment that explains
// it; the pin reaches the commands that read it and the policy prefill.
func TestTemplates_PairInstallIntent(t *testing.T) {
	for _, dir := range templateSources {
		for _, purpose := range []string{"", InstallPurposeInternet, InstallPurposeInternal, InstallPurposeBoth} {
			d := pairData(t, "K7QM-4ZTD")
			if err := (InstallIntent{Purpose: purpose}).Apply(&d); err != nil {
				t.Fatal(err)
			}
			out := render(t, dir, d)
			want := purpose == InstallPurposeInternal || purpose == InstallPurposeBoth
			for name, text := range map[string]string{"docker": out.Docker, "compose": out.Compose,
				"kubernetes": out.Kubernetes, "cli": out.CLI} {
				if got := strings.Count(text, "SENSOR_ALLOW_PRIVATE_TARGETS"); (got > 0) != want {
					t.Errorf("[%s purpose=%q] %s mentions the private switch %d times:\n%s", dir, purpose, name, got, text)
				}
				if want && !strings.Contains(text, "lets this sensor scan private networks") {
					t.Errorf("[%s purpose=%q] %s does not explain the private switch", dir, purpose, name)
				}
				if strings.Contains(text, "SENSOR_ALLOWED_RANGES=") || strings.Contains(text, "SENSOR_ALLOWED_RANGES:") {
					t.Errorf("[%s purpose=%q] %s pins ranges nobody asked for", dir, purpose, name)
				}
			}
			bashSyntaxOK(t, dir+" intent docker", out.Docker)
			continuationLinesOK(t, dir+" intent docker", out.Docker)
		}

		d := pairData(t, "K7QM-4ZTD")
		if err := (InstallIntent{Purpose: InstallPurposeInternal, AllowedRanges: []string{"10.0.0.0/16", "192.168.10.0/24"}}).Apply(&d); err != nil {
			t.Fatal(err)
		}
		out := render(t, dir, d)
		for name, want := range map[string]string{
			"docker":  "-e SENSOR_ALLOWED_RANGES='10.0.0.0/16,192.168.10.0/24' \\",
			"compose": `SENSOR_ALLOWED_RANGES: "10.0.0.0/16,192.168.10.0/24"`,
			"cli":     "SENSOR_ALLOWED_RANGES=10.0.0.0/16,192.168.10.0/24",
			"policy":  `- "10.0.0.0/16"`,
		} {
			text := map[string]string{"docker": out.Docker, "compose": out.Compose, "cli": out.CLI, "policy": out.Policy}[name]
			if !strings.Contains(text, want) {
				t.Errorf("[%s] pinned %s lacks %q:\n%s", dir, name, want, text)
			}
		}
		if !strings.Contains(out.Policy, "allow_private: true") || !strings.Contains(out.Policy, "The networks you listed") {
			t.Errorf("[%s] pinned policy:\n%s", dir, out.Policy)
		}
		bashSyntaxOK(t, dir+" pinned docker", out.Docker)
		continuationLinesOK(t, dir+" pinned docker", out.Docker)
	}
}

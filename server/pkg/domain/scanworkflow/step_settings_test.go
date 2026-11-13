package scanworkflow

import (
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeStepConfig_Naabu(t *testing.T) {
	got, err := NormalizeStepConfig("naabu", map[string]any{
		"ports": " 80, 443,8000-8100 ", "rate": "500", "retries": float64(0), "scan_type": "syn",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"ports": "80,443,8000-8100", "rate": int64(500), "retries": int64(0), "scan_type": "syn"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v\nwant %#v", got, want)
	}
	for _, ports := range []any{"top-100", "top-1000", "full", float64(22)} {
		if _, err := NormalizeStepConfig("naabu", map[string]any{"ports": ports}); err != nil {
			t.Errorf("ports %v: %v", ports, err)
		}
	}
	if got, _ := NormalizeStepConfig("NAABU", map[string]any{"top_ports": "1000"}); got["top_ports"] != int64(1000) {
		t.Errorf("top_ports = %#v", got["top_ports"])
	}
}

func TestNormalizeStepConfig_Nuclei(t *testing.T) {
	in := map[string]any{"tags": "CVE, exposure,cve", "exclude_tags": []any{"dos"}, "severity": "High,critical", "templates": []any{"cves"}}
	got, err := NormalizeStepConfig("nuclei", in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["tags"], []string{"cve", "exposure"}) ||
		!reflect.DeepEqual(got["exclude_tags"], []string{"dos"}) ||
		!reflect.DeepEqual(got["severity"], []string{"high", "critical"}) ||
		!reflect.DeepEqual(got["templates"], []any{"cves"}) {
		t.Errorf("got %#v", got)
	}
	if in["tags"] != "CVE, exposure,cve" {
		t.Error("the step's own config was modified")
	}
}

// SECURITY: values a sensor would refuse are refused when the step is saved.
func TestNormalizeStepConfig_Refused(t *testing.T) {
	cases := []struct {
		tool   string
		config map[string]any
	}{
		{"naabu", map[string]any{"ports": "-"}},
		{"naabu", map[string]any{"ports": "-p 1-65535"}},
		{"naabu", map[string]any{"ports": "80\n-o /etc/x"}},
		{"naabu", map[string]any{"ports": "80;id"}},
		{"naabu", map[string]any{"ports": "0"}},
		{"naabu", map[string]any{"ports": "443-80"}},
		{"naabu", map[string]any{"ports": float64(80.5)}},
		{"naabu", map[string]any{"exclude_ports": "full"}},
		{"naabu", map[string]any{"top_ports": float64(65535)}},
		{"naabu", map[string]any{"ports": "80", "top_ports": "100"}},
		{"naabu", map[string]any{"rate": float64(1e9)}},
		{"naabu", map[string]any{"retries": "many"}},
		{"nuclei", map[string]any{"tags": []any{"-code"}}},
		{"nuclei", map[string]any{"tags": []any{"cve -headless"}}},
		{"nuclei", map[string]any{"tags": []any{"fuzz"}}},
		{"nuclei", map[string]any{"tags": []any{float64(1)}}},
		{"nuclei", map[string]any{"exclude_tags": []any{"-t /etc"}}},
		{"nuclei", map[string]any{"severity": []any{}}},
		{"nuclei", map[string]any{"severity": "info,-o"}},
		{"httpx", map[string]any{"allow_interactsh": true}},
		{"", map[string]any{"exclude": []any{"--config=/tmp/x"}}},
		{"", map[string]any{"exclude": "a\x00b"}},
	}
	for _, tc := range cases {
		if _, err := NormalizeStepConfig(tc.tool, tc.config); !errors.Is(err, ErrInvalidStepSetting) {
			t.Errorf("%s %#v: err = %v", tc.tool, tc.config, err)
		}
	}
}

// A tool whose sensor declares no settings keeps its config as it is.
func TestNormalizeStepConfig_OtherTools(t *testing.T) {
	in := map[string]any{"threads": float64(30), "all": true}
	got, err := NormalizeStepConfig("subfinder", in)
	if err != nil || !reflect.DeepEqual(got, in) {
		t.Errorf("got %#v, %v", got, err)
	}
	if got, err := NormalizeStepConfig("naabu", nil); got != nil || err != nil {
		t.Errorf("nil config: %v, %v", got, err)
	}
}

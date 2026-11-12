package sensor

import "testing"

func TestRedactPlatformText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The sensor host's own addresses go.
		{"dial tcp 10.1.2.3:5432: refused", "dial tcp [platform]:5432: refused"},
		{"from 192.168.0.7 and 172.16.4.4", "from [platform] and [platform]"},
		{"bound 127.0.0.1 and ::1", "bound [platform] and [platform]"},
		{"pod 100.64.3.9 link fe80::1", "pod [platform] link [platform]"},
		{"metadata 169.254.169.254", "metadata [platform]"},
		// Its file system goes.
		{"open /opt/sensor/templates/x.yaml: no such file", "open [platform]: no such file"},
		{`{"path":"/home/runner/.cache/nuclei"}`, `{"path":"[platform]"}`},
		{"cwd=/var/lib/sensor", "cwd=[platform]"},
		// The tenant's public targets and URLs stay.
		{"scanning 93.184.216.34 and example.com", "scanning 93.184.216.34 and example.com"},
		{"GET https://example.com/var/www/index.html 200", "GET https://example.com/var/www/index.html 200"},
		{"2001:4860:4860::8888 answered", "2001:4860:4860::8888 answered"},
		// Look-alikes that are not addresses or roots stay.
		{"at 10:00:01 found 3 variables", "at 10:00:01 found 3 variables"},
		{"version 1.2.3.4567", "version 1.2.3.4567"},
		{"", ""},
	} {
		if got := RedactPlatformText(tc.in); got != tc.want {
			t.Errorf("RedactPlatformText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRedactPlatformValue(t *testing.T) {
	in := map[string]any{
		"host":  "10.0.0.9",
		"n":     3.0,
		"nest":  []any{"/tmp/x", "example.org", true},
		"inner": map[string]any{"ip": "8.8.8.8"},
	}
	out := RedactPlatformValue(in).(map[string]any)
	if out["host"] != PlatformRedacted || out["n"] != 3.0 {
		t.Fatalf("top level: %v", out)
	}
	nest := out["nest"].([]any)
	if nest[0] != PlatformRedacted || nest[1] != "example.org" || nest[2] != true {
		t.Fatalf("nested slice: %v", nest)
	}
	if out["inner"].(map[string]any)["ip"] != "8.8.8.8" {
		t.Fatalf("public address masked: %v", out["inner"])
	}
	if in["host"] != "10.0.0.9" {
		t.Fatal("input modified")
	}
}

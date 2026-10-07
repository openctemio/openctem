package sensor

import (
	"encoding/json"
	"strings"
	"testing"
)

func enforced(s LocalPolicySummary) *LocalPolicyReport {
	return &LocalPolicyReport{State: LocalPolicyEnforced, Summary: &s}
}

func TestJobOf(t *testing.T) {
	for name, tc := range map[string]struct {
		typ, payload string
		want         Job
	}{
		"scanner wins":         {"scan", `{"scanner":"Nuclei","scanner_name":"x","preferred_tool":"y"}`, Job{Type: "scan", Tool: "nuclei"}},
		"scanner_name":         {"scan", `{"scanner_name":"httpx"}`, Job{Type: "scan", Tool: "httpx"}},
		"preferred_tool":       {"scan", `{"preferred_tool":"naabu"}`, Job{Type: "scan", Tool: "naabu"}},
		"retired name":         {"scan", `{"scanner":"gitleaks"}`, Job{Type: "scan", Tool: "betterleaks"}},
		"collector":            {"collect", `{"collector":"Subfinder"}`, Job{Type: "collect", Tool: "subfinder"}},
		"nuclei validation":    {"validate", `{"executor_kind":"nuclei"}`, Job{Type: "validate", Tool: "nuclei"}},
		"safe-check validate":  {"validate", `{"executor_kind":"tcp"}`, Job{Type: "validate"}},
		"interactsh bool":      {"scan", `{"scanner":"nuclei","config":{"allow_interactsh":true}}`, Job{Type: "scan", Tool: "nuclei", Interactsh: true}},
		"interactsh string":    {"scan", `{"scanner":"nuclei","config":{"allow_interactsh":"TRUE"}}`, Job{Type: "scan", Tool: "nuclei", Interactsh: true}},
		"interactsh false":     {"scan", `{"scanner":"nuclei","config":{"allow_interactsh":false}}`, Job{Type: "scan", Tool: "nuclei"}},
		"custom templates":     {"scan", `{"scanner":"nuclei","custom_templates":[{},{}]}`, Job{Type: "scan", Tool: "nuclei", CustomTemplates: 2}},
		"ports string":         {"scan", `{"scanner":"naabu","config":{"ports":"80,443"}}`, Job{Type: "scan", Tool: "naabu", Ports: "80,443"}},
		"ports number":         {"scan", `{"scanner":"naabu","config":{"ports":8443}}`, Job{Type: "scan", Tool: "naabu", Ports: "8443"}},
		"private address":      {"scan", `{"scanner":"nmap","targets":["10.0.0.0/24"]}`, Job{Type: "scan", Tool: "nmap", Private: true, PrivateAddress: true}},
		"private name only":    {"scan", `{"scanner":"nmap","target":"db.internal"}`, Job{Type: "scan", Tool: "nmap", Private: true}},
		"public":               {"scan", `{"scanner":"nmap","target":"203.0.113.4"}`, Job{Type: "scan", Tool: "nmap"}},
		"unreadable payload":   {"scan", `not json`, Job{Type: "scan", Private: true}},
		"empty payload":        {"health_check", ``, Job{Type: "health_check"}},
		"loopback not policy":  {"scan", `{"scanner":"nmap","target":"127.0.0.1"}`, Job{Type: "scan", Tool: "nmap", Private: true}},
		"private url and port": {"scan", `{"scanner":"httpx","target":"https://192.168.1.10:8443/x"}`, Job{Type: "scan", Tool: "httpx", Private: true, PrivateAddress: true}},
	} {
		if got := JobOf(tc.typ, json.RawMessage(tc.payload)); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

func TestAccepts(t *testing.T) {
	scan := Job{Type: "scan", Tool: "nuclei"}
	for name, tc := range map[string]struct {
		report    *LocalPolicyReport
		job       Job
		opts      DispatchOptions
		wantLayer string
		wantRule  string
	}{
		// Without a report or without a policy the sensor decides nothing
		// the platform could know of; the absent policy allows both opt-ins.
		"no report":                {nil, Job{Type: "scan", Tool: "x", Interactsh: true, CustomTemplates: 1}, DispatchOptions{}, "", ""},
		"absent policy":            {&LocalPolicyReport{State: LocalPolicyAbsent}, Job{Type: "scan", Interactsh: true, CustomTemplates: 3}, DispatchOptions{}, "", ""},
		"enforced without summary": {&LocalPolicyReport{State: LocalPolicyEnforced}, Job{Type: "scan", Interactsh: true}, DispatchOptions{}, "", ""},

		"kill switch withholds everything": {&LocalPolicyReport{State: LocalPolicyAbsent, KillSwitch: true}, Job{Type: "health_check"}, DispatchOptions{}, RefusalLayerLocal, RuleKillSwitch},

		"private needs a policy (none)":   {nil, Job{Type: "scan", Private: true}, DispatchOptions{RequireLocalPolicyForPrivate: true}, RefusalLayerManaged, RulePrivateNeedsLocalPlcy},
		"private needs a policy (absent)": {&LocalPolicyReport{State: LocalPolicyAbsent}, Job{Type: "scan", Private: true}, DispatchOptions{RequireLocalPolicyForPrivate: true}, RefusalLayerManaged, RulePrivateNeedsLocalPlcy},
		"private with a policy":           {enforced(LocalPolicySummary{AllowPrivate: true}), Job{Type: "scan", Private: true, PrivateAddress: true}, DispatchOptions{RequireLocalPolicyForPrivate: true}, "", ""},
		"private, switch off":             {nil, Job{Type: "scan", Private: true}, DispatchOptions{}, "", ""},

		"checks allow":         {enforced(LocalPolicySummary{Checks: []string{"scan"}}), scan, DispatchOptions{}, "", ""},
		"checks refuse":        {enforced(LocalPolicySummary{Checks: []string{"validate"}}), scan, DispatchOptions{}, RefusalLayerLocal, RuleChecksAllow},
		"checks empty refuses": {enforced(LocalPolicySummary{Checks: []string{}}), scan, DispatchOptions{}, RefusalLayerLocal, RuleChecksAllow},
		"health check always":  {enforced(LocalPolicySummary{Checks: []string{}}), Job{Type: "health_check"}, DispatchOptions{}, "", ""},

		"tools allow":          {enforced(LocalPolicySummary{Tools: []string{"nuclei"}}), scan, DispatchOptions{}, "", ""},
		"tools refuse":         {enforced(LocalPolicySummary{Tools: []string{"httpx"}}), scan, DispatchOptions{}, RefusalLayerLocal, RuleToolsAllow},
		"scan names no tool":   {enforced(LocalPolicySummary{Tools: []string{"httpx"}}), Job{Type: "scan"}, DispatchOptions{}, RefusalLayerLocal, RuleToolsAllow},
		"validate without one": {enforced(LocalPolicySummary{Tools: []string{"httpx"}}), Job{Type: "validate"}, DispatchOptions{}, "", ""},

		"custom templates refused": {enforced(LocalPolicySummary{}), Job{Type: "scan", Tool: "nuclei", CustomTemplates: 1}, DispatchOptions{}, RefusalLayerLocal, RuleAllowCustomTemplates},
		"custom templates allowed": {enforced(LocalPolicySummary{AllowCustomTemplates: true}), Job{Type: "scan", Tool: "nuclei", CustomTemplates: 1}, DispatchOptions{}, "", ""},
		"interactsh refused":       {enforced(LocalPolicySummary{}), Job{Type: "scan", Tool: "nuclei", Interactsh: true}, DispatchOptions{}, RefusalLayerLocal, RuleAllowInteractsh},
		"interactsh allowed":       {enforced(LocalPolicySummary{AllowInteractsh: true}), Job{Type: "scan", Tool: "nuclei", Interactsh: true}, DispatchOptions{}, "", ""},

		"ports inside":           {enforced(LocalPolicySummary{Ports: "80,443,8000-8999"}), Job{Type: "scan", Tool: "naabu", Ports: "443,8000-8100"}, DispatchOptions{}, "", ""},
		"ports across ranges":    {enforced(LocalPolicySummary{Ports: "1-100,101-200"}), Job{Type: "scan", Tool: "naabu", Ports: "50-150"}, DispatchOptions{}, "", ""},
		"ports outside":          {enforced(LocalPolicySummary{Ports: "80,443"}), Job{Type: "scan", Tool: "naabu", Ports: "22,80"}, DispatchOptions{}, RefusalLayerLocal, RulePortsAllow},
		"named list: sensor":     {enforced(LocalPolicySummary{Ports: "80,443"}), Job{Type: "scan", Tool: "naabu", Ports: "top-100"}, DispatchOptions{}, "", ""},
		"ports any in policy":    {enforced(LocalPolicySummary{}), Job{Type: "scan", Tool: "naabu", Ports: "1-65535"}, DispatchOptions{}, "", ""},
		"private address refuse": {enforced(LocalPolicySummary{}), Job{Type: "scan", Tool: "nmap", Private: true, PrivateAddress: true}, DispatchOptions{}, RefusalLayerLocal, RuleTargetsAllowPrivate},
		"private name: sensor":   {enforced(LocalPolicySummary{}), Job{Type: "scan", Tool: "nmap", Private: true}, DispatchOptions{}, "", ""},
	} {
		got := Accepts(tc.report, tc.job, tc.opts)
		switch {
		case tc.wantRule == "" && got != nil:
			t.Errorf("%s: refused %+v, want accepted", name, got)
		case tc.wantRule != "" && got == nil:
			t.Errorf("%s: accepted, want %s/%s", name, tc.wantLayer, tc.wantRule)
		case got != nil && (got.Layer != tc.wantLayer || got.Rule != tc.wantRule || got.Detail == ""):
			t.Errorf("%s: %+v, want %s/%s with a detail", name, got, tc.wantLayer, tc.wantRule)
		}
	}
}

func TestHasPrivateAddress(t *testing.T) {
	for payload, want := range map[string]bool{
		`{"target":"10.1.2.3"}`:                        true,
		`{"targets":["198.51.100.1","172.20.0.0/16"]}`: true,
		`{"targets":["0.0.0.0/0"]}`:                    false, // overlaps, not inside: the sensor decides
		`{"target":"[fd00::1]:443"}`:                   true,
		`{"target":{"address":"192.168.0.9:22"}}`:      true,
		`{"target":"db.internal"}`:                     false, // a name: resolved on the sensor
		`{"target":"127.0.0.1"}`:                       false, // built-in deny list, not allow_private
		`{"target":"100.64.1.1"}`:                      false,
		`not json`:                                     false,
	} {
		if got := HasPrivateAddress(json.RawMessage(payload)); got != want {
			t.Errorf("%s: %v, want %v", payload, got, want)
		}
	}
}

func TestAccepts_OptIns(t *testing.T) {
	oast := Job{Type: "scan", Tool: "nuclei", Interactsh: true}
	tmpl := Job{Type: "scan", Tool: "nuclei", CustomTemplates: 1}
	legacy := &LocalPolicyReport{State: LocalPolicyAbsent} // allows both opt-ins locally
	off := DispatchOptions{OptIns: &OptIns{}}
	for name, tc := range map[string]struct {
		job      Job
		opts     DispatchOptions
		wantRule string
	}{
		"interactsh, default off":     {oast, off, RuleAllowInteractsh},
		"templates, default off":      {tmpl, off, RuleAllowCustomTemplates},
		"plain job, default off":      {Job{Type: "scan", Tool: "nuclei"}, off, ""},
		"interactsh enabled":          {oast, DispatchOptions{OptIns: &OptIns{AllowInteractsh: true}}, ""},
		"templates enabled":           {tmpl, DispatchOptions{OptIns: &OptIns{AllowCustomTemplates: true}}, ""},
		"not evaluated (nil opt-ins)": {oast, DispatchOptions{}, ""},
	} {
		got := Accepts(legacy, tc.job, tc.opts)
		switch {
		case tc.wantRule == "" && got != nil:
			t.Errorf("%s: refused %+v", name, got)
		case tc.wantRule != "" && (got == nil || got.Layer != RefusalLayerManaged || got.Rule != tc.wantRule):
			t.Errorf("%s: %+v, want managed/%s", name, got, tc.wantRule)
		}
	}
	// Enabled at the organization but refused by the sensor's own policy:
	// the local refusal stands (the platform never widens the sensor).
	strict := &LocalPolicyReport{State: LocalPolicyEnforced, Summary: &LocalPolicySummary{TargetsAllow: -1}}
	if got := Accepts(strict, oast, DispatchOptions{OptIns: &OptIns{AllowInteractsh: true}}); got == nil || got.Layer != RefusalLayerLocal {
		t.Errorf("enabled but locally refused: %+v", got)
	}
}

func TestRefusalOf(t *testing.T) {
	if RefusalOf(nil, "connection reset") != nil {
		t.Fatal("an ordinary failure read as a refusal")
	}
	got := RefusalOf(nil, "refused by local policy: tools.allow: nuclei is not allowed on this sensor")
	if got == nil || got.Layer != RefusalLayerLocal || got.Rule != "tools.allow" || got.Detail != "nuclei is not allowed on this sensor" {
		t.Fatalf("text refusal: %+v", got)
	}
	if got.Message() != "refused by local policy: tools.allow: nuclei is not allowed on this sensor" {
		t.Fatalf("message %q does not keep the prefix", got.Message())
	}
	// A structured refusal is sanitized: unknown layer and malformed rule
	// are not stored as sent, control characters are removed.
	got = RefusalOf(&DispatchRefusal{Layer: "Root\n", Rule: "rm -rf /", Detail: "x\u202ey\nz"}, "")
	if got.Layer != "unknown" || got.Rule != "unknown" || strings.ContainsAny(got.Detail, "\n\u202e") {
		t.Fatalf("sanitized: %+v", got)
	}
	got = RefusalOf(&DispatchRefusal{Layer: "managed", Rule: "allow_interactsh"}, "anything")
	if got.Layer != RefusalLayerManaged || got.Message() != "refused by the managed policy: allow_interactsh" {
		t.Fatalf("structured: %+v %q", got, got.Message())
	}
}

// A service on a private address is private in every name form
// (research/63 PR0): host:port:proto, host:port/proto, [v6]:port/proto.
func TestPrivateTarget_ServiceNames(t *testing.T) {
	for target, want := range map[string]bool{
		"10.0.0.5:22:tcp":         true,
		"10.0.0.5:22/tcp":         true,
		"[fd00::5]:443/tcp":       true,
		"fd00::5:443:tcp":         true,
		"192.168.1.9:3389:tcp":    true,
		"8.8.8.8:53:udp":          false,
		"198.51.100.7:443/tcp":    false,
		"db.internal:5432:tcp":    true,
		"vndirect.com.vn:443:tcp": false,
	} {
		if got := isPrivateTarget(target); got != want {
			t.Errorf("isPrivateTarget(%q) = %v, want %v", target, got, want)
		}
	}
	for target, want := range map[string]bool{
		"10.0.0.5:22:tcp": true, "10.0.0.5:22/tcp": true, "[fd00::5]:443:tcp": true, "8.8.8.8:53:udp": false,
	} {
		if got := isPrivateAddressLiteral(target); got != want {
			t.Errorf("isPrivateAddressLiteral(%q) = %v, want %v", target, got, want)
		}
	}
}

package main

import (
	"strings"
	"testing"
)

// withKinds is the minimal registry plus a service section and a
// values_from attribute.
func withKinds(kinds string) string {
	reg := strings.Replace(minimal, "types:\n", `service_categories:
  - { id: web, label: Web, label_vi: Web }
  - { id: remote_access, label: Remote access, label_vi: Truy cập từ xa }
kind_sources:
  - { id: fingerprint, label: Fingerprint, label_vi: Dấu vân tay, confidence: 95 }
  - { id: port_guess, label: Guess, label_vi: Đoán, confidence: 30 }
service_kinds:
`+kinds+"types:\n", 1)
	reg = strings.Replace(reg, "      - { name: provider, type: enum, values: [github], facet: true }\n",
		"      - { name: provider, type: enum, values: [github], facet: true }\n      - { name: service_kind, type: enum, values_from: service_kinds, facet: true, derived: true }\n", 1)
	reg = strings.Replace(reg, "  provider: { label: Provider, label_vi: Nhà cung cấp }\n",
		"  provider: { label: Provider, label_vi: Nhà cung cấp }\n  service_kind: { label: Service kind, label_vi: Loại dịch vụ }\n", 1)
	return reg
}

const goodKinds = `  - { id: http, label: HTTP, category: web, tcp: [80, 443], tls_aliases: [https] }
  - { id: rdp, label: RDP, category: remote_access, tcp: [3389], aliases: [ms-wbt-server], risk: high }
  - { id: docker-api, label: Docker API, category: remote_access, tcp: [2375], risk: high, risk_anonymous: critical }
`

func TestResolveServiceKinds(t *testing.T) {
	if err := resolveText(t, withKinds(goodKinds), minimalRel); err != nil {
		t.Fatalf("good service kinds rejected: %v", err)
	}
	cases := []struct{ name, kinds, want string }{
		{"duplicate port", goodKinds + "  - { id: ssh, label: SSH, category: remote_access, tcp: [80] }\n", "already belongs"},
		{"alias names two kinds", goodKinds + "  - { id: ssh, label: SSH, category: remote_access, aliases: [https] }\n", "already names"},
		{"alias is another id", goodKinds + "  - { id: ssh, label: SSH, category: remote_access, aliases: [rdp] }\n", "already names"},
		{"alias not normal", goodKinds + "  - { id: ssh, label: SSH, category: remote_access, aliases: [Open_SSH] }\n", "normal form"},
		{"unknown category", goodKinds + "  - { id: ssh, label: SSH, category: nope }\n", "unknown category"},
		{"bad risk", goodKinds + "  - { id: ssh, label: SSH, category: web, risk: severe }\n", "risk"},
		{"anonymous below risk", goodKinds + "  - { id: ssh, label: SSH, category: web, risk: high, risk_anonymous: low }\n", "risk_anonymous"},
		{"anonymous without risk", goodKinds + "  - { id: ssh, label: SSH, category: web, risk_anonymous: high }\n", "risk_anonymous"},
		{"bad id", goodKinds + "  - { id: SSH, label: SSH, category: web }\n", "lower case"},
		{"port out of range", goodKinds + "  - { id: ssh, label: SSH, category: web, tcp: [70000] }\n", "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := resolveText(t, withKinds(tc.kinds), minimalRel)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestResolveServiceKinds_ValuesFrom(t *testing.T) {
	reg := withKinds(goodKinds)
	if err := resolveText(t, strings.Replace(reg, "values_from: service_kinds", "values_from: nope", 1), minimalRel); err == nil {
		t.Fatal("unknown values_from accepted")
	}
	if err := resolveText(t, strings.Replace(reg, "type: enum, values_from: service_kinds", "type: string, values_from: service_kinds", 1), minimalRel); err == nil {
		t.Fatal("values_from on a string accepted")
	}
	if err := resolveText(t, strings.Replace(reg, "{ id: fingerprint, label: Fingerprint, label_vi: Dấu vân tay, confidence: 95 }",
		"{ id: fingerprint, label: Fingerprint, label_vi: Dấu vân tay, confidence: 20 }", 1), minimalRel); err == nil {
		t.Fatal("kind sources out of confidence order accepted")
	}
}

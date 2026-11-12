package asset

import (
	"strings"
	"testing"
)

// The classification table: what a producer's name or a bare port becomes.
func TestClassifyService_Table(t *testing.T) {
	cases := []struct {
		name     string
		subType  string
		incoming map[string]any
		stored   map[string]any
		evidence KindSource
		want     ServiceClassification
		ok       bool
	}{
		{"iana rdp name", "open_port", map[string]any{"protocol": "ms-wbt-server", "port": 3389}, nil, KindSourceFingerprint,
			ServiceClassification{Kind: "rdp", Category: "remote_access", Source: KindSourceFingerprint}, true},
		{"smb by iana name", "open_port", map[string]any{"protocol": "microsoft-ds"}, nil, KindSourceReported,
			ServiceClassification{Kind: "smb", Category: "file_share", Source: KindSourceReported}, true},
		{"https is http with tls", "open_port", map[string]any{"protocol": "https"}, nil, KindSourceFingerprint,
			ServiceClassification{Kind: "http", Category: "web", Source: KindSourceFingerprint, TLS: true}, true},
		{"ssl prefix means tls", "open_port", map[string]any{"protocol": "ssl/imap"}, nil, KindSourceReported,
			ServiceClassification{Kind: "imap", Category: "mail", Source: KindSourceReported, TLS: true}, true},
		{"ldaps", "open_port", map[string]any{"protocol": "LDAPS"}, nil, KindSourceFingerprint,
			ServiceClassification{Kind: "ldap", Category: "directory_auth", Source: KindSourceFingerprint, TLS: true}, true},
		{"underscore and case", "open_port", map[string]any{"protocol": "Docker_S"}, nil, KindSourceFingerprint,
			ServiceClassification{Kind: "docker-api", Category: "container_orchestration", Source: KindSourceFingerprint, TLS: true}, true},
		{"sftp is ssh", "open_port", map[string]any{"protocol": "sftp"}, nil, KindSourceReported,
			ServiceClassification{Kind: "ssh", Category: "remote_access", Source: KindSourceReported}, true},
		{"modbus", "open_port", map[string]any{"protocol": "modbus"}, nil, KindSourceFingerprint,
			ServiceClassification{Kind: "modbus", Category: "industrial_ot", Source: KindSourceFingerprint}, true},
		{"trailing question mark is a guess", "open_port", map[string]any{"protocol": "ssh?"}, nil, KindSourceReported,
			ServiceClassification{Kind: "ssh", Category: "remote_access", Source: KindSourcePortGuess}, true},
		{"transport in protocol falls to the port", "open_port", map[string]any{"protocol": "tcp", "port": 6379}, nil, KindSourceReported,
			ServiceClassification{Kind: "redis", Category: "cache", Source: KindSourcePortGuess}, true},
		{"port guess from stored port", "open_port", map[string]any{}, map[string]any{"port": float64(3306)}, KindSourceReported,
			ServiceClassification{Kind: "mysql", Category: "database", Source: KindSourcePortGuess}, true},
		{"port guess never sets tls", "open_port", map[string]any{"port": 993}, nil, KindSourceFingerprint,
			ServiceClassification{Kind: "imap", Category: "mail", Source: KindSourcePortGuess}, true},
		{"udp port guess", "open_port", map[string]any{"port": 161, "transport": "udp"}, nil, KindSourceReported,
			ServiceClassification{Kind: "snmp", Category: "network_mgmt", Source: KindSourcePortGuess}, true},
		{"tcp 161 is no snmp", "open_port", map[string]any{"port": 161, "transport": "tcp"}, nil, KindSourceReported,
			ServiceClassification{}, false},
		{"unlisted port", "open_port", map[string]any{"port": 5000}, nil, KindSourceReported, ServiceClassification{}, false},
		{"measured unknown name never guesses", "open_port", map[string]any{"protocol": "acme-proto", "port": 443}, nil, KindSourceFingerprint,
			ServiceClassification{}, false},
		{"web service speaks http", "http", map[string]any{}, map[string]any{"scheme": "https", "port": 22}, KindSourceHTTPProbe,
			ServiceClassification{Kind: "http", Category: "web", Source: KindSourceHTTPProbe, TLS: true}, true},
		{"a guess evidence is read as reported", "open_port", map[string]any{"protocol": "redis"}, nil, KindSourcePortGuess,
			ServiceClassification{Kind: "redis", Category: "cache", Source: KindSourceReported}, true},
		{"unknown evidence is reported", "open_port", map[string]any{"protocol": "redis"}, nil, KindSource("forged"),
			ServiceClassification{Kind: "redis", Category: "cache", Source: KindSourceReported}, true},
		{"port out of range", "open_port", map[string]any{"port": 70000}, nil, KindSourceReported, ServiceClassification{}, false},
		{"oversized name is no protocol", "open_port", map[string]any{"protocol": strings.Repeat("a", 65), "port": 22}, nil, KindSourceReported,
			ServiceClassification{Kind: "ssh", Category: "remote_access", Source: KindSourcePortGuess}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ClassifyService(tc.subType, tc.incoming, tc.stored, tc.evidence)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("ClassifyService = %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// A port guess never overwrites a measured kind; a fingerprint overwrites a
// guess; an equal source overwrites (the service changed).
func TestApplyServiceClassification_Precedence(t *testing.T) {
	props := map[string]any{}
	guess := ServiceClassification{Kind: "http", Category: "web", Source: KindSourcePortGuess}
	if !ApplyServiceClassification(props, guess) || props[PropKeyKindSource] != "port_guess" {
		t.Fatalf("guess not applied: %v", props)
	}
	fp := ServiceClassification{Kind: "ssh", Category: "remote_access", Source: KindSourceFingerprint}
	if !ApplyServiceClassification(props, fp) || props[PropKeyServiceKind] != "ssh" {
		t.Fatalf("fingerprint did not replace the guess: %v", props)
	}
	if ApplyServiceClassification(props, guess) || props[PropKeyServiceKind] != "ssh" {
		t.Fatalf("a guess overwrote a fingerprint: %v", props)
	}
	rep := ServiceClassification{Kind: "telnet", Category: "remote_access", Source: KindSourceReported}
	if ApplyServiceClassification(props, rep) || props[PropKeyServiceKind] != "ssh" {
		t.Fatalf("a report overwrote a fingerprint: %v", props)
	}
	fp2 := ServiceClassification{Kind: "redis", Category: "cache", Source: KindSourceFingerprint}
	if !ApplyServiceClassification(props, fp2) || props[PropKeyServiceKind] != "redis" || props[PropKeyServiceCategory] != "cache" {
		t.Fatalf("an equal source did not overwrite: %v", props)
	}
	// A stored source without a kind (a damaged row) is overwritten.
	broken := map[string]any{PropKeyKindSource: "fingerprint"}
	if !ApplyServiceClassification(broken, guess) || broken[PropKeyServiceKind] != "http" {
		t.Fatalf("source without kind kept: %v", broken)
	}
	// Measured TLS sets has_tls; a guess never does.
	tlsProps := map[string]any{}
	ApplyServiceClassification(tlsProps, ServiceClassification{Kind: "http", Category: "web", Source: KindSourcePortGuess, TLS: true})
	if _, ok := tlsProps["has_tls"]; ok {
		t.Fatalf("guess set has_tls")
	}
}

func TestAssetClassifyService(t *testing.T) {
	a, err := NewAssetWithSubType("203.0.113.5:3389:tcp", AssetTypeService, "open_port", CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.SetProperties(map[string]any{"port": 3389, "transport": "tcp"})
	a.ClassifyService(map[string]any{"port": 3389}, KindSourceReported)
	if k, src := ServiceKindOf(a.Properties()); k != "rdp" || src != KindSourcePortGuess {
		t.Fatalf("guess: %s %s", k, src)
	}
	a.ClassifyService(map[string]any{"protocol": "rdp"}, KindSourceFingerprint)
	if k, src := ServiceKindOf(a.Properties()); k != "rdp" || src != KindSourceFingerprint {
		t.Fatalf("fingerprint: %s %s", k, src)
	}
	// Another type is never classified.
	d, _ := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	d.ClassifyService(map[string]any{"protocol": "rdp"}, KindSourceFingerprint)
	if _, ok := d.Properties()[PropKeyServiceKind]; ok {
		t.Fatal("domain classified")
	}
}

// A hostile banner or name can never invent a kind or category: kinds come
// only from the closed table.
func TestParseServiceProtocol_Hostile(t *testing.T) {
	for _, raw := range []string{
		"<script>alert(1)</script>", "ssh\r\nINJECTED", "\x1b[31mredis", "rdp\x00", "../../etc/passwd",
		strings.Repeat("x", 10000), "ssl/ssl/ssl/", "?", "????",
	} {
		p := ParseServiceProtocol(raw)
		if p.Kind != "" {
			t.Errorf("%q gave kind %q", raw, p.Kind)
		}
	}
}

// Registry invariants the generator checks, asserted on the generated data.
func TestServiceKindRegistry(t *testing.T) {
	ports := map[string]string{}
	for _, k := range ServiceKinds() {
		if !IsServiceCategory(k.Category) {
			t.Errorf("%s: unknown category %s", k.ID, k.Category)
		}
		for _, p := range k.TCP {
			if prev := ports[portKeyOf("tcp", p)]; prev != "" {
				t.Errorf("tcp/%d in %s and %s", p, prev, k.ID)
			}
			ports[portKeyOf("tcp", p)] = k.ID
		}
		if k.RiskAnonymous != "" && k.Risk == "" {
			t.Errorf("%s: risk_anonymous without risk", k.ID)
		}
	}
	prev := 101
	for _, s := range registryKindSources {
		if s.Confidence >= prev {
			t.Errorf("kind sources not in descending confidence at %s", s.ID)
		}
		prev = s.Confidence
	}
	if !KindSourcePortGuess.IsGuess() || KindSourcePortGuess.Confidence() >= KindSourceReported.Confidence() {
		t.Error("port guess must be the lowest source")
	}
	for _, k := range []string{PropKeyServiceKind, PropKeyServiceCategory, PropKeyKindSource} {
		if !IsReservedPropertyKey(k) {
			t.Errorf("%s must be reserved", k)
		}
	}
}

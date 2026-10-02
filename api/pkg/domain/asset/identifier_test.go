package asset

import "testing"

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"00:1A:2B:3C:4D:5E", "00:1a:2b:3c:4d:5e", true},
		{"00-1a-2b-3c-4d-5e", "00:1a:2b:3c:4d:5e", true},
		{"001A2B3C4D5E", "00:1a:2b:3c:4d:5e", true},
		{"02:42:ac:11:00:02", "", false}, // Docker: locally administered
		{"ff:ff:ff:ff:ff:ff", "", false}, // broadcast
		{"01:00:5e:00:00:01", "", false}, // multicast
		{"00:00:00:00:00:00", "", false},
		{"00:00:5e:00:01:0a", "", false}, // VRRP virtual router
		{"00:00:0c:07:ac:01", "", false}, // HSRP
		{"00:05:9a:3c:7a:00", "", false}, // Cisco AnyConnect, shared by every install
		{"50:50:54:50:30:30", "", false}, // Windows WAN Miniport
		{"not-a-mac", "", false},
	}
	for _, tt := range tests {
		got, ok := NormalizeMAC(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("NormalizeMAC(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestNormalizeIdentifierPlaceholders(t *testing.T) {
	for _, tt := range []struct {
		kind IdentifierKind
		in   string
		ok   bool
	}{
		{IdentifierBIOSUUID, "00000000-0000-0000-0000-000000000000", false},
		{IdentifierBIOSUUID, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", false},
		{IdentifierBIOSUUID, "03000200-0400-0500-0006-000700080009", false},
		{IdentifierBIOSUUID, "{4C4C4544-0042-3510-8051-B4C04F4E4D32}", true},
		{IdentifierSerial, "To be filled by O.E.M.", false},
		{IdentifierSerial, "Default string", false},
		{IdentifierSerial, "B5QNM32", true},
		{IdentifierHostname, "localhost", false},
		{IdentifierHostname, "10.0.0.1", false},
		{IdentifierIP, "127.0.0.1", false},
		{IdentifierIP, "::ffff:10.0.0.1", true},
		{IdentifierCloudID, "I-0ABC123", true},
	} {
		if _, ok := NormalizeIdentifier(tt.kind, tt.in); ok != tt.ok {
			t.Errorf("NormalizeIdentifier(%s, %q) ok = %v, want %v", tt.kind, tt.in, ok, tt.ok)
		}
	}
	if v, _ := NormalizeIdentifier(IdentifierBIOSUUID, "{4C4C4544-0042-3510-8051-B4C04F4E4D32}"); v != "4c4c4544-0042-3510-8051-b4c04f4e4d32" {
		t.Errorf("BIOS UUID not canonical: %q", v)
	}
	if v, _ := NormalizeIdentifier(IdentifierCloudID, "arn:aws:ec2:us-east-1:123:instance/i-0ABC"); v != "arn:aws:ec2:us-east-1:123:instance/i-0ABC" {
		t.Errorf("ARN case changed: %q", v)
	}
}

func TestIdentifierKindOrder(t *testing.T) {
	order := []IdentifierKind{IdentifierHostID, IdentifierCloudID, IdentifierBIOSUUID, IdentifierSerial,
		IdentifierMAC, IdentifierSCMRepoID, IdentifierFQDN, IdentifierHostname, IdentifierIP}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Fatalf("%s must rank above %s", order[i-1], order[i])
		}
	}
	for _, k := range order {
		strong := k.Rank() <= IdentifierSCMRepoID.Rank()
		if k.IsStrong() != strong {
			t.Errorf("%s IsStrong = %v", k, k.IsStrong())
		}
	}
	if IdentifierMAC.IsSingleValued() {
		t.Error("a host has several MACs; MAC must not veto")
	}
}

func TestSCMRepoIdentifier(t *testing.T) {
	if got := SCMRepoIdentifier("github.com/acme/repo", "123"); got != "github.com:123" {
		t.Errorf("got %q", got)
	}
	if got := SCMRepoIdentifier("acme/repo", "123"); got != "123" {
		t.Errorf("got %q", got)
	}
}

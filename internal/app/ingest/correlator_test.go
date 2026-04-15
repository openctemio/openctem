package ingest

import (
	"testing"
)

func TestExtractAllIPs(t *testing.T) {
	tests := []struct {
		name       string
		assetName  string
		properties map[string]any
		wantCount  int
		wantIPs    []string
	}{
		{
			name:      "IP as name",
			assetName: "192.168.1.10",
			wantCount: 1,
			wantIPs:   []string{"192.168.1.10"},
		},
		{
			name:       "IP in properties.ip",
			assetName:  "web-server",
			properties: map[string]any{"ip": "10.0.0.1"},
			wantCount:  1,
			wantIPs:    []string{"10.0.0.1"},
		},
		{
			name:      "IP in properties.ip_address.address",
			assetName: "web-server",
			properties: map[string]any{
				"ip_address": map[string]any{"address": "10.0.0.2"},
			},
			wantCount: 1,
			wantIPs:   []string{"10.0.0.2"},
		},
		{
			name:      "IPs in properties.ip_addresses array",
			assetName: "web-server",
			properties: map[string]any{
				"ip_addresses": []any{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
			},
			wantCount: 3,
		},
		{
			name:      "All sources combined, deduped",
			assetName: "10.0.0.1",
			properties: map[string]any{
				"ip":           "10.0.0.1",
				"ip_address":   map[string]any{"address": "10.0.0.2"},
				"ip_addresses": []any{"10.0.0.1", "10.0.0.3"},
			},
			wantCount: 3, // 10.0.0.1 (deduped), 10.0.0.2, 10.0.0.3
		},
		{
			name:       "No IPs",
			assetName:  "web-server",
			properties: map[string]any{"hostname": "web-server"},
			wantCount:  0,
		},
		{
			name:       "Nil properties",
			assetName:  "web-server",
			properties: nil,
			wantCount:  0,
		},
		{
			name:       "Invalid IP ignored",
			assetName:  "not-an-ip",
			properties: map[string]any{"ip": "also-not-ip"},
			wantCount:  0,
		},
		{
			name:      "IPv6 canonical",
			assetName: "2001:db8::1",
			properties: map[string]any{
				"ip_addresses": []any{"2001:0db8:0000:0000:0000:0000:0000:0001"}, // same as name
			},
			wantCount: 1, // deduped after canonical
		},
		{
			name:      "String array type",
			assetName: "server",
			properties: map[string]any{
				"ip_addresses": []string{"172.16.0.1", "172.16.0.2"},
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractAllIPs(tt.properties, tt.assetName)
			if len(got) != tt.wantCount {
				t.Errorf("ExtractAllIPs() got %d IPs %v, want %d", len(got), got, tt.wantCount)
			}
			for _, wantIP := range tt.wantIPs {
				found := false
				for _, g := range got {
					if g == wantIP {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ExtractAllIPs() missing expected IP %s in %v", wantIP, got)
				}
			}
		})
	}
}

func TestNameQuality(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"", 0},
		{"192.168.1.1", 10},
		{"2001:db8::1", 10},
		{"server01", 30},
		{"web-01", 30},
		{"server01.corp.local", 50},
		{"web-01.example.com", 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nameQuality(tt.name)
			if got != tt.want {
				t.Errorf("nameQuality(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

func TestLooksLikeIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"2001:db8::1", true},
		{"::1", true},
		{"web-server", false},
		{"example.com", false},
		{"192.168.1", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := looksLikeIP(tt.input)
			if got != tt.want {
				t.Errorf("looksLikeIP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

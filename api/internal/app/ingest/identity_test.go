package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

func kinds(ids []asset.Identifier) map[asset.IdentifierKind][]string {
	out := map[asset.IdentifierKind][]string{}
	for _, id := range ids {
		out[id.Kind] = append(out[id.Kind], id.Value)
	}
	return out
}

func TestIdentifiersFor_Host(t *testing.T) {
	ca := &ctis.Asset{
		Type: ctis.AssetTypeHost, Value: "web01.corp.example",
		Properties: ctis.Properties{
			"mac_address":  "00:1a:2b:3c:4d:5e\n02:42:ac:11:00:02",
			"ip_address":   "10.0.0.5",
			"instance_id":  "i-0abc",
			"bios_uuid":    "00000000-0000-0000-0000-000000000000",
			"netbios_name": "WEB01",
		},
		Identifiers: &ctis.AssetIdentifiers{MachineID: "abc123", SerialNumber: "B5QNM32"},
	}
	got := kinds(identifiersFor(ca, asset.AssetTypeHost, "web01.corp.example"))
	want := map[asset.IdentifierKind][]string{
		asset.IdentifierHostID:   {"abc123"},
		asset.IdentifierSerial:   {"B5QNM32"},
		asset.IdentifierCloudID:  {"i-0abc"},
		asset.IdentifierMAC:      {"00:1a:2b:3c:4d:5e"},
		asset.IdentifierFQDN:     {"web01.corp.example"},
		asset.IdentifierHostname: {"web01"},
		asset.IdentifierIP:       {"10.0.0.5"},
	}
	for k, v := range want {
		if len(got[k]) != len(v) || got[k][0] != v[0] {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if len(got[asset.IdentifierBIOSUUID]) != 0 {
		t.Errorf("placeholder BIOS UUID recorded: %v", got[asset.IdentifierBIOSUUID])
	}
}

func TestIdentifiersFor_RepositoryAndDomain(t *testing.T) {
	repo := &ctis.Asset{Type: ctis.AssetTypeRepository, Value: "github.com/acme/r", Properties: ctis.Properties{"repo_id": float64(98765)}}
	if got := kinds(identifiersFor(repo, asset.AssetTypeRepository, "github.com/acme/r")); got[asset.IdentifierSCMRepoID][0] != "github.com:98765" {
		t.Errorf("repo identifiers = %v", got)
	}
	// MAC on a repository is not a hardware identifier.
	repo.Properties["mac_address"] = "00:1a:2b:3c:4d:5e"
	if got := kinds(identifiersFor(repo, asset.AssetTypeRepository, "github.com/acme/r")); len(got[asset.IdentifierMAC]) != 0 {
		t.Errorf("repository got a MAC: %v", got)
	}
	dom := &ctis.Asset{Type: ctis.AssetTypeDomain, Value: "example.com", Properties: ctis.Properties{"instance_id": "i-1"}}
	if got := identifiersFor(dom, asset.AssetTypeDomain, "example.com"); len(got) != 0 {
		t.Errorf("domains stay keyed by name, got %v", got)
	}
}

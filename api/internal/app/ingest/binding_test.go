package ingest

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestCommandTargets(t *testing.T) {
	cmd := &command.Command{Payload: []byte(`{"targets":["a.example.com"," b.example.com ","a.example.com",7],"target":"10.0.0.0/24"}`)}
	got := CommandTargets(cmd)
	want := []string{"a.example.com", "b.example.com", "10.0.0.0/24"}
	if len(got) != len(want) {
		t.Fatalf("targets %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets %v, want %v", got, want)
		}
	}
	if CommandTargets(&command.Command{Payload: []byte(`not json`)}) != nil || CommandTargets(nil) != nil {
		t.Fatal("unparseable payload must have no targets")
	}
}

func TestAlterScopeCoverage(t *testing.T) {
	tid := shared.NewID()
	mk := func(name string, typ asset.AssetType) *asset.Asset {
		a, err := asset.NewAssetWithTenant(tid, name, typ, asset.CriticalityMedium)
		if err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return a
	}
	cases := []struct {
		name    string
		targets []string
		asset   *asset.Asset
		want    bool
	}{
		{"same host", []string{"db-1.corp.example"}, mk("db-1.corp.example", asset.AssetTypeHost), true},
		{"url target covers its host", []string{"https://App.Example.com:443/login"}, mk("app.example.com", asset.AssetTypeDomain), true},
		{"url target, other host", []string{"https://app.example.com/login"}, mk("db.example.com", asset.AssetTypeSubdomain), false},
		{"host target covers subdomain", []string{"example.com"}, mk("api.example.com", asset.AssetTypeSubdomain), true},
		{"suffix is not a subdomain", []string{"example.com"}, mk("badexample.com", asset.AssetTypeDomain), false},
		{"cidr covers ip", []string{"10.0.0.0/24"}, mk("10.0.0.7", asset.AssetTypeIPAddress), true},
		{"cidr misses ip", []string{"10.0.0.0/24"}, mk("10.0.1.7", asset.AssetTypeIPAddress), false},
		{"repo url covers repo", []string{"https://github.com/acme/app.git"}, mk("github.com/acme/app", asset.AssetTypeRepository), true},
		{"scp-style repo", []string{"git@github.com:acme/app.git"}, mk("github.com/acme/app", asset.AssetTypeRepository), true},
		{"other repo on the same host", []string{"https://github.com/acme/app"}, mk("github.com/acme/other", asset.AssetTypeRepository), false},
		{"org covers its repos", []string{"github.com/acme"}, mk("github.com/acme/app", asset.AssetTypeRepository), true},
		{"no targets cover nothing", nil, mk("db-1.corp.example", asset.AssetTypeHost), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAlterScope(Binding{Kind: BindingCommand, Targets: tc.targets})
			if got := s.mayAlter(tc.asset); got != tc.want {
				t.Fatalf("mayAlter(%q) with targets %v = %v, want %v", tc.asset.Name(), tc.targets, got, tc.want)
			}
		})
	}

	if newAlterScope(Binding{}).mayAlter(mk("db-1.corp.example", asset.AssetTypeHost)) {
		t.Fatal("an unsolicited report may alter an existing asset")
	}
	if !newAlterScope(TrustedBinding()).mayAlter(mk("db-1.corp.example", asset.AssetTypeHost)) {
		t.Fatal("a trusted ingest may not alter an existing asset")
	}
}

func TestRoleMayPushUnsolicited(t *testing.T) {
	for typ, want := range map[sensor.SensorType]bool{
		"runner": false, sensor.SensorTypeCollector: true,
		sensor.SensorTypeWorker: false, sensor.SensorTypeEASM: false, "": false,
	} {
		if got := RoleMayPushUnsolicited(typ); got != want {
			t.Errorf("RoleMayPushUnsolicited(%q) = %v, want %v", typ, got, want)
		}
	}
}

package asset

import (
	"testing"
)

// The stored name of a new asset must equal the key every lookup uses:
// NormalizeName(name, coreType, subType) after ResolveTypeAlias. Creating
// with a different key stores names no lookup finds (RFC-043 section 10).
func TestNewAssetWithSubType_NameEqualsLookupKey(t *testing.T) {
	names := []string{
		"https://API.Example.com:443/",
		"http://shop.example.com:80/cart?x=1",
		"api.example.com:8443/tcp",
		"10.0.0.1:443",
		"s3://My-Bucket",
		"my-bucket.s3.amazonaws.com",
		"Registry.Example.com:443/",
		"arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa",
		"Example.COM.",
	}
	for alias := range TypeAliases {
		core, sub := ResolveTypeAlias(alias)
		for _, n := range names {
			a, err := NewAssetWithSubType(n, core, sub, CriticalityMedium)
			if err != nil {
				continue // a name the type refuses is not a key mismatch
			}
			if want := NormalizeName(n, core, sub); a.Name() != want {
				t.Errorf("%s (%s/%s): stored %q, lookup key %q", n, core, sub, a.Name(), want)
			}
			if a.SubType() != sub {
				t.Errorf("%s (%s/%s): sub-type %q not recorded", n, core, sub, a.SubType())
			}
			// A caller that passes the alias type itself (manual API, CSV)
			// must land on the same name as ingest.
			if got := NormalizeName(n, alias, ""); got != a.Name() {
				t.Errorf("%s: alias type %s normalizes to %q, ingest stores %q", n, alias, got, a.Name())
			}
		}
	}
}

func TestNormalizeName_HTTPServiceSpellingsAreOneName(t *testing.T) {
	core, sub := ResolveTypeAlias(AssetTypeHTTPService)
	for _, n := range []string{"https://api.example.com", "https://api.example.com:443", "HTTPS://API.example.com/"} {
		a, err := NewAssetWithSubType(n, core, sub, CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "https://api.example.com" {
			t.Errorf("%q stored as %q, want https://api.example.com", n, a.Name())
		}
	}
}

func TestNormalizeName_CloudResourceIDsAreNotDNSNames(t *testing.T) {
	tests := []struct {
		name     string
		typ      AssetType
		sub      string
		in, want string
	}{
		{"ec2 a", AssetTypeHost, "compute", "arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa", "arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa"},
		{"ec2 b", AssetTypeHost, "compute", "arn:aws:ec2:us-east-1:123456789012:instance/i-0bbb", "arn:aws:ec2:us-east-1:123456789012:instance/i-0bbb"},
		{"lambda keeps case", AssetTypeHost, "serverless", "arn:aws:lambda:eu-west-1:123456789012:function:MyFunc", "arn:aws:lambda:eu-west-1:123456789012:function:MyFunc"},
		{"ARN prefix case", AssetTypeHost, "compute", "ARN:aws:ec2:us-east-1:123456789012:instance/i-0aaa", "arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa"},
		{"azure lower-case", AssetTypeHost, "compute", "/subscriptions/ABC/resourceGroups/RG1/providers/Microsoft.Compute/virtualMachines/VM1", "/subscriptions/abc/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1"},
		{"gcp full", AssetTypeHost, "compute", "//compute.googleapis.com/projects/p1/zones/us-central1-a/instances/vm-1", "//compute.googleapis.com/projects/p1/zones/us-central1-a/instances/vm-1"},
		{"gcp relative", AssetTypeHost, "compute", "projects/p1/zones/us-central1-a/instances/vm-1", "projects/p1/zones/us-central1-a/instances/vm-1"},
		{"compute alias type", AssetTypeCompute, "", "arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa", "arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa"},
		{"plain host still normalized", AssetTypeHost, "compute", "Web-1.Example.com.", "web-1.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeName(tt.in, tt.typ, tt.sub); got != tt.want {
				t.Errorf("NormalizeName(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if got := NormalizeName(NormalizeName(tt.in, tt.typ, tt.sub), tt.typ, tt.sub); got != tt.want {
				t.Errorf("not idempotent: %q", got)
			}
		})
	}
	a := NormalizeName("arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa", AssetTypeHost, "compute")
	b := NormalizeName("arn:aws:ec2:us-east-1:123456789012:instance/i-0bbb", AssetTypeHost, "compute")
	if a == b {
		t.Fatalf("two EC2 instances share the name %q", a)
	}
}

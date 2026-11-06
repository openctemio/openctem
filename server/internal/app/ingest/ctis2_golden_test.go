package ingest

import (
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Same input, same record: each finding below is the CTIS 2.0 form of a
// finding a CTIS 1.6 producer sent before the switch. The keys were captured
// from the 1.x receiver (develop before the switch, same asset id and tool,
// with the version-3 finding identity): the version-1 composite and base, and
// the current identity key. A 2.0 report
// of the same observation must land on the same stored finding.
func TestCTIS2KeepsFindingKeys(t *testing.T) {
	asset := shared.MustIDFromString("0193a000-0000-7000-8000-000000000001")
	tool := &ctis.Tool{Name: "golden-tool"}
	cve := func(ids ...string) *ctis.VulnerabilityDetails {
		v := &ctis.VulnerabilityDetails{}
		for _, id := range ids {
			v.AddID(id, "")
		}
		return v
	}
	sca := cve("CVE-2021-23337")
	sca.PURL, sca.PackageName, sca.InstalledVersion = "pkg:npm/lodash@4.17.20", "lodash", "4.17.20"
	cases := []struct {
		name                string
		f                   ctis.Finding
		composite, base, v2 string
	}{
		{"network", ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "OpenSSH", Severity: ctis.SeverityHigh, RuleID: "plugin-1",
			Vulnerability: cve("CVE-2024-6387"), Network: &ctis.NetworkLocation{Port: 22, Transport: ctis.TransportTCP}},
			"94e8ce35c450fb54be150cfae10c489daa8aa2d21932233b496e18fe461b3faf",
			"1e88315a16c655dd7ee9ff64fc3239dc568090f994c8fb37ddf000c016bbe0a4",
			"d0ea8e0414bfbeb54c3db92859038f50968ab539793b75827aeb21f0f3498225"},
		{"sca", ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "lodash", Severity: ctis.SeverityHigh, RuleID: "CVE-2021-23337",
			Vulnerability: sca},
			"b82b27c82ac581217d78d9f63a772eb77b9f395e331ab861985aef4ce3819128",
			"9f1db051a46c4baac14700fead4409a55b87a5daeaecc735132329518c73a91b",
			"4db6b2115f9889fd0622feae3e69582f39829e70b5876e5dcadb185a23380bfa"},
		{"sast", ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "SQLi", Severity: ctis.SeverityHigh, RuleID: "go.sqli",
			Location: &ctis.FindingLocation{Path: "db/query.go", StartLine: 42, EndLine: 42, Snippet: "db.Query(\"SELECT * FROM t WHERE id=\" + id)"}},
			"10270fb91257a4e674e858eebd27aaff3f66c12c5d8002cef0cc808a36230f2e",
			"d5952842d0238cff81eb0d8dea45f6a37ad60cf954ee16a012499af4c03fbd54",
			"bbba6cf9416cf858c1ad90227a3ff787757d639eebde3226aeaca2251a9e32de"},
		{"dast", ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "XSS", Severity: ctis.SeverityMedium, RuleID: "xss-reflected",
			Location: &ctis.FindingLocation{Path: "https://app.example.com/search?q=1"}, Web: &ctis.WebLocation{Method: "GET"}},
			"17f0dcbe99f66cf4c0687a9b23bc45f51dff82bf6131146c92e12e506489f372",
			"10296d161c1362a85ac8d3a94bb5238af73629810e2ffbfc05b860cce0b4d652",
			"cb5f5227fe5870a868969f25ca795c71ceb62fe47b734cbb371af3a94c88fa8b"},
		{"misconfig", ctis.Finding{Type: ctis.FindingTypeMisconfiguration, Title: "S3 public", Severity: ctis.SeverityHigh, RuleID: "AVD-AWS-0086",
			Misconfiguration: &ctis.MisconfigurationDetails{PolicyID: "AVD-AWS-0086", ResourceType: "aws_s3_bucket", ResourceName: "logs"},
			Location:         &ctis.FindingLocation{Path: "main.tf", StartLine: 3}},
			"b8dc30ab45a509d6a338cfe168993d1d19c1973f0ccd5afca6c348244f71aa77",
			"817fddf90b66c1372bcd16d5cc4d0ece4e60daed331cf35aa224f40037190013",
			"713a51614c997f523144c5d62c5c1fac8ca7cfc954376f4b7901070e2f39f59b"},
		{"generic", ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "Weak TLS", Severity: ctis.SeverityLow, RuleID: "tls-weak"},
			"2af980553064cd3f1849df422c128a4627f3410924fa8e0433ccc39204bb5fe8",
			"6425330bd370a647c1cee8f38de57fd1b60c941774288a331885279247c985fb",
			""},
	}
	for _, c := range cases {
		f := c.f
		comp, base := generateFindingFingerprint(asset, &f, tool)
		if comp != c.composite || base != c.base {
			t.Errorf("%s: version-1 key %s/%s, want %s/%s (a 2.0 report would split the finding)", c.name, comp, base, c.composite, c.base)
		}
		v2 := ""
		if k, ok := identityV2(asset, &f, "", 0); ok {
			v2 = k.Fingerprint()
		}
		if v2 != c.v2 {
			t.Errorf("%s: version-2 key %q, want %q", c.name, v2, c.v2)
		}
	}
}

// Same input, same record for assets: the CTIS 2.0 form of each asset a 1.6
// producer sent lands on the stored (type, sub-type, name) the 1.x receiver
// gave it (captured on develop before the switch), so no asset is split.
func TestCTIS2KeepsAssetKeys(t *testing.T) {
	ident := func(kind ctis.IdentityKind) *ctis.AssetTechnical {
		return &ctis.AssetTechnical{Identity: &ctis.IdentityTechnical{Kind: kind}}
	}
	cases := []struct {
		was string // the CTIS 1.6 wire type
		a   ctis.Asset
		// stored type, sub-type and name the 1.x receiver gave it
		typ, sub, name string
	}{
		{"domain", ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "example.com"}, "domain", "", "example.com"},
		{"subdomain", ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "api.example.com"}, "subdomain", "", "api.example.com"},
		{"subdomain", ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "shop.example.co.uk"}, "subdomain", "", "shop.example.co.uk"},
		{"ip_address", ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: "2001:db8::1"}, "ip_address", "", "2001:db8::1"},
		{"http_service", ctis.Asset{Type: ctis.AssetTypeWebOrigin, Value: "https://app.example.com"}, "service", "http", "https://app.example.com"},
		{"open_port", ctis.Asset{Type: ctis.AssetTypeService, Value: "203.0.113.5:443/tcp"}, "service", "open_port", "203.0.113.5:443:tcp"},
		{"host", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web01.corp.example"}, "host", "", "web01.corp.example"},
		{"server", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web02.corp.example"}, "host", "", "web02.corp.example"},
		{"network", ctis.Asset{Type: ctis.AssetTypeIPRange, Value: "10.0.0.0/8"}, "network", "", "10.0.0.0/8"},
		{"iam_user", ctis.Asset{Type: ctis.AssetTypeIdentity, Value: "arn:aws:iam::123456789012:user/alice", Technical: ident(ctis.IdentityUser)},
			"identity", "iam_user", "arn:aws:iam::123456789012:user/alice"},
		{"kubernetes_cluster", ctis.Asset{Type: ctis.AssetTypeKubernetesCluster, Value: "prod-eks"}, "kubernetes", "cluster", "prod-eks"},
		{"repository", ctis.Asset{Type: ctis.AssetTypeRepository, Value: "github.com/acme/api"}, "repository", "", "github.com/acme/api"},
		{"certificate", ctis.Asset{Type: ctis.AssetTypeCertificate, Value: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			"certificate", "", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}
	for _, c := range cases {
		a := c.a
		if _, err := ctis.CanonicalAssetValue(a.Type, a.Value); err != nil {
			t.Fatalf("%s: fixture value %q is not canonical: %v", c.was, a.Value, err)
		}
		rt := resolveCTISAssetType(&a)
		name := asset.NormalizeName(getAssetName(&a), rt.normType, rt.normSubType)
		if string(rt.stored.Type) != c.typ || rt.stored.SubType != c.sub || name != c.name {
			t.Errorf("%s -> %s: stored %s/%s %q, want %s/%s %q", c.was, a.Type, rt.stored.Type, rt.stored.SubType, name, c.typ, c.sub, c.name)
		}
	}
}

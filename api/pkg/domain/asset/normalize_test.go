package asset

import (
	"testing"
)

func TestNormalizeName_Idempotent(t *testing.T) {
	// NormalizeName(NormalizeName(x)) == NormalizeName(x) for all types
	cases := []struct {
		name      string
		assetType AssetType
		subType   string
	}{
		{"Example.COM", AssetTypeDomain, ""},
		{"api.example.com.", AssetTypeSubdomain, ""},
		{"192.168.001.010", AssetTypeIPAddress, ""},
		{"2001:0db8::0001", AssetTypeIPAddress, ""},
		{"Web-Server-01.corp.local.", AssetTypeHost, ""},
		{"https://github.com/Org/Repo.git", AssetTypeRepository, ""},
		{"HTTPS://API.Example.COM:443/v1/", AssetTypeApplication, ""},
		{"192.168.1.10:443/tcp", AssetTypeService, "open_port"},
		{"https://api.example.com:443", AssetTypeService, "http"},
		{"*.Example.COM", AssetTypeCertificate, ""},
		{"postgres://user:pass@db.example.com:5432/mydb?ssl=true", AssetTypeDatabase, ""},
		{"192.168.1.0/24", AssetTypeNetwork, ""},
		{"s3://my-bucket", AssetTypeStorage, "s3_bucket"},
		{"com.Company.App", AssetTypeMobileApp, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := NormalizeName(tc.name, tc.assetType, tc.subType)
			second := NormalizeName(first, tc.assetType, tc.subType)
			if first != second {
				t.Errorf("not idempotent:\n  input:  %q\n  first:  %q\n  second: %q", tc.name, first, second)
			}
			if first == "" {
				t.Errorf("normalized to empty string from %q", tc.name)
			}
		})
	}
}

// ─── Domain ──────────────────────────────────────────────────────────

func TestNormalizeDNSName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// D1: Case variation
		{"Example.COM", "example.com"},
		{"API.EXAMPLE.COM", "api.example.com"},
		// D2: Trailing dot
		{"example.com.", "example.com"},
		{"api.example.com.", "api.example.com"},
		// D3: Leading dot
		{".example.com", "example.com"},
		// D4: Whitespace
		{" example.com ", "example.com"},
		{"\texample.com\n", "example.com"},
		// D8: With port (strip for domain type)
		{"example.com:443", "example.com"},
		// D9: With protocol
		{"https://example.com", "example.com"},
		{"http://example.com/path", "example.com"},
		// D10: Wildcard preserved
		{"*.example.com", "*.example.com"},
		// D2+D1: Combined
		{"Example.COM.", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeDomain, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, domain) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── IP Address ──────────────────────────────────────────────────────

func TestNormalizeIPAddress(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// I1: IPv4 standard
		{"192.168.1.1", "192.168.1.1"},
		// I3: IPv4-mapped IPv6 → IPv4
		{"::ffff:192.168.1.1", "192.168.1.1"},
		// I2: IPv6 full → short
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"2001:0db8::0001", "2001:db8::1"},
		// I4: Zone ID stripped
		{"fe80::1%eth0", "fe80::1"},
		// I8: With port stripped
		{"192.168.1.1:443", "192.168.1.1"},
		// I9: /32 CIDR stripped
		{"192.168.1.1/32", "192.168.1.1"},
		{"2001:db8::1/128", "2001:db8::1"},
		// I10: Protocol stripped
		{"https://192.168.1.1", "192.168.1.1"},
		// I12: Brackets stripped
		{"[2001:db8::1]", "2001:db8::1"},
		// Whitespace
		{" 10.0.0.1 ", "10.0.0.1"},
		// Loopback
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeIPAddress, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, ip_address) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── Host ────────────────────────────────────────────────────────────

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// H3: Case
		{"Web-Server-01", "web-server-01"},
		{"SERVER.CORP.LOCAL", "server.corp.local"},
		// H4: Trailing dot
		{"server.corp.local.", "server.corp.local"},
		// H11: IPv6 host
		{"2001:0db8::0001", "2001:db8::1"},
		// Host that is an IP
		{"192.168.1.10", "192.168.1.10"},
		// With protocol
		{"https://myhost.local", "myhost.local"},
		// With port
		{"myhost.local:22", "myhost.local"},
		// FQDN
		{"web-01.corp.local.", "web-01.corp.local"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeHost, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, host) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── Repository ──────────────────────────────────────────────────────

func TestNormalizeRepo(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// R1: HTTPS
		{"https://github.com/Org/Repo", "github.com/org/repo"},
		// R1: SSH
		{"git@github.com:Org/Repo.git", "github.com/org/repo"},
		// R2: .git suffix
		{"github.com/Org/Repo.git", "github.com/org/repo"},
		// R3: Case
		{"github.com/ORG/REPO", "github.com/org/repo"},
		// R4: Different platforms preserved
		{"gitlab.com/org/repo", "gitlab.com/org/repo"},
		{"bitbucket.org/org/repo", "bitbucket.org/org/repo"},
		// R5: Without host
		{"org/repo", "org/repo"},
		// R6: Bare name
		{"repo", "repo"},
		// R12: Azure DevOps
		{"dev.azure.com/org/project/_git/repo", "dev.azure.com/org/project/repo"},
		// R14: Trailing slash
		{"github.com/org/repo/", "github.com/org/repo"},
		// R15: Branch reference stripped
		{"github.com/org/repo/tree/main", "github.com/org/repo"},
		{"github.com/org/repo/blob/main/file.go", "github.com/org/repo"},
		// HTTP prefix
		{"http://github.com/org/repo", "github.com/org/repo"},
		// Combined: HTTPS + .git + case
		{"HTTPS://GitHub.com/Org/Repo.GIT", "github.com/org/repo"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeRepository, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, repository) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── URL / Application ───────────────────────────────────────────────

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Default port stripped
		{"https://api.example.com:443", "https://api.example.com"},
		{"http://app.example.com:80/path", "http://app.example.com/path"},
		// Non-default port kept
		{"https://api.example.com:8443/v1", "https://api.example.com:8443/v1"},
		// Trailing slash stripped
		{"https://api.example.com/", "https://api.example.com"},
		// Host lowercased
		{"HTTPS://API.Example.COM/v1", "https://api.example.com/v1"},
		// Query stripped
		{"https://api.example.com/v1?key=val", "https://api.example.com/v1"},
		// No scheme
		{"api.example.com/v1", "api.example.com/v1"},
		// Path preserved
		{"https://api.example.com/v1/users", "https://api.example.com/v1/users"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeApplication, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, application) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── Service ─────────────────────────────────────────────────────────

func TestNormalizeService(t *testing.T) {
	tests := []struct {
		input   string
		subType string
		want    string
	}{
		// open_port: normalize separator
		{"192.168.1.10:443/tcp", "open_port", "192.168.1.10:443:tcp"},
		{"192.168.1.10:443:tcp", "open_port", "192.168.1.10:443:tcp"},
		// open_port: default protocol
		{"192.168.1.10:443", "open_port", "192.168.1.10:443:tcp"},
		// open_port: UDP preserved
		{"192.168.1.10:53:udp", "open_port", "192.168.1.10:53:udp"},
		// http: URL normalize
		{"https://api.example.com:443", "http", "https://api.example.com"},
		{"HTTPS://API.Example.COM/v1/", "http", "https://api.example.com/v1"},
		// discovered_url: URL normalize
		{"https://app.com/login?ref=1", "discovered_url", "https://app.com/login"},
	}
	for _, tt := range tests {
		t.Run(tt.input+"_"+tt.subType, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeService, tt.subType)
			if got != tt.want {
				t.Errorf("NormalizeName(%q, service/%s) = %q, want %q", tt.input, tt.subType, got, tt.want)
			}
		})
	}
}

// ─── Certificate ─────────────────────────────────────────────────────

func TestNormalizeCert(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"*.Example.COM", "*.example.com"},
		{"example.com.", "example.com"},
		{"*.Example.COM.", "*.example.com"},
		// Fingerprint normalization
		{"SHA256:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
			"sha256abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeCertificate, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, certificate) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── Database ────────────────────────────────────────────────────────

func TestNormalizeDatabase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Strip protocol
		{"postgres://db.example.com:5432/mydb", "db.example.com:5432/mydb"},
		{"postgresql://db.example.com:5432/mydb", "db.example.com:5432/mydb"},
		{"mysql://db.example.com:3306/mydb", "db.example.com:3306/mydb"},
		// Strip credentials
		{"postgres://user:pass@db.example.com:5432/mydb", "db.example.com:5432/mydb"},
		// Strip query params
		{"db.example.com:5432/mydb?ssl=true", "db.example.com:5432/mydb"},
		// Lowercase
		{"DB.Example.COM:5432/MyDB", "db.example.com:5432/mydb"},
		// Plain name
		{"my-database", "my-database"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeDatabase, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, database) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── Network ─────────────────────────────────────────────────────────

func TestNormalizeNetwork(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Canonical CIDR
		{"192.168.1.0/24", "192.168.1.0/24"},
		// Non-canonical CIDR (host bits zeroed)
		{"192.168.1.100/24", "192.168.1.0/24"},
		// IPv6 CIDR
		{"2001:db8::/32", "2001:db8::/32"},
		// Plain name
		{"prod-network", "prod-network"},
		// VPC
		{"VPC-ABC123", "vpc-abc123"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assetType := AssetTypeNetwork
			if tt.input == "VPC-ABC123" {
				assetType = AssetTypeVPC
			}
			got := NormalizeName(tt.input, assetType, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, network) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── Storage ─────────────────────────────────────────────────────────

func TestNormalizeStorage(t *testing.T) {
	tests := []struct {
		input   string
		subType string
		want    string
	}{
		// S3: strip prefix
		{"s3://my-bucket", "s3_bucket", "my-bucket"},
		{"S3://My-Bucket", "s3_bucket", "my-bucket"},
		// S3: virtual-hosted URL
		{"my-bucket.s3.amazonaws.com", "s3_bucket", "my-bucket"},
		{"my-bucket.s3.us-east-1.amazonaws.com", "s3_bucket", "my-bucket"},
		// S3: path-style URL
		{"s3.amazonaws.com/my-bucket", "s3_bucket", "my-bucket"},
		// Container registry
		{"REGISTRY.IO/org/image:latest", "container_registry", "registry.io/org/image:latest"},
	}
	for _, tt := range tests {
		t.Run(tt.input+"_"+tt.subType, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeStorage, tt.subType)
			if got != tt.want {
				t.Errorf("NormalizeName(%q, storage/%s) = %q, want %q", tt.input, tt.subType, got, tt.want)
			}
		})
	}
}

// ─── Cross-cutting ───────────────────────────────────────────────────

func TestCommonNormalize(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"null bytes", "name\x00injected", "nameinjected"},
		{"zero-width space", "exam\u200Bple.com", "example.com"},
		{"BOM", "\uFEFFexample.com", "example.com"},
		{"control chars", "name\x01with\x02ctrl", "name with ctrl"},
		{"whitespace trim", "  name  ", "name"},
		{"multiple spaces", "name  with   spaces", "name with spaces"},
		{"empty", "", ""},
		{"only spaces", "   ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commonNormalize(tt.input)
			if got != tt.want {
				t.Errorf("commonNormalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── Misc types ──────────────────────────────────────────────────────

func TestNormalizeMiscTypes(t *testing.T) {
	// Container: lowercase
	if got := NormalizeName("My-Container", AssetTypeContainer, ""); got != "my-container" {
		t.Errorf("container: got %q, want %q", got, "my-container")
	}
	// Kubernetes: lowercase
	if got := NormalizeName("Prod-Cluster", AssetTypeKubernetes, ""); got != "prod-cluster" {
		t.Errorf("kubernetes: got %q, want %q", got, "prod-cluster")
	}
	// Mobile app: lowercase
	if got := NormalizeName("com.Company.App", AssetTypeMobileApp, ""); got != "com.company.app" {
		t.Errorf("mobile_app: got %q, want %q", got, "com.company.app")
	}
	// Cloud account: lowercase
	if got := NormalizeName("Prod-Account", AssetTypeCloudAccount, ""); got != "prod-account" {
		t.Errorf("cloud_account: got %q, want %q", got, "prod-account")
	}
	// Identity: preserve case (ARN is case-sensitive)
	if got := NormalizeName("arn:aws:iam::123:user/Admin", AssetTypeIdentity, ""); got != "arn:aws:iam::123:user/Admin" {
		t.Errorf("identity: got %q, want %q", got, "arn:aws:iam::123:user/Admin")
	}
	// Unclassified: trim only
	if got := NormalizeName(" My Asset ", AssetTypeUnclassified, ""); got != "My Asset" {
		t.Errorf("unclassified: got %q, want %q", got, "My Asset")
	}
}

// ─── RFC Appendix Edge Cases ─────────────────────────────────────────

func TestNormalizeServiceOpenPort(t *testing.T) {
	tests := []struct {
		input   string
		subType string
		want    string
	}{
		// Different protocol preserved
		{"192.168.1.10:53:udp", "open_port", "192.168.1.10:53:udp"},
		// Default to tcp when no protocol
		{"10.0.0.1:22", "open_port", "10.0.0.1:22:tcp"},
		// IPv6 host with port and protocol
		{"[2001:db8::1]:443:tcp", "open_port", "2001:db8::1:443:tcp"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeService, tt.subType)
			if got != tt.want {
				t.Errorf("NormalizeName(%q, service/%s) = %q, want %q", tt.input, tt.subType, got, tt.want)
			}
		})
	}
}

func TestNormalizeApplicationEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// www is a subdomain — different from bare domain
		{"https://www.example.com", "https://www.example.com"},
		{"https://example.com", "https://example.com"},
		// Different paths are different assets
		{"https://app.example.com/v1", "https://app.example.com/v1"},
		{"https://app.example.com/v2", "https://app.example.com/v2"},
		// Query params stripped
		{"https://api.example.com?key=val", "https://api.example.com"},
		// Strip default port 80 for http
		{"http://app.test:80/path", "http://app.test/path"},
		// No scheme — keep without scheme
		{"app.example.com", "app.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeApplication, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, application) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeRepoEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Different platforms are different assets
		{"github.com/org/repo", "github.com/org/repo"},
		{"gitlab.com/org/repo", "gitlab.com/org/repo"},
		// Azure DevOps _git stripped
		{"dev.azure.com/org/project/_git/repo", "dev.azure.com/org/project/repo"},
		// Branch path stripped
		{"github.com/org/repo/tree/main/src", "github.com/org/repo"},
		// Combined: HTTPS + .git + case (verify existing behavior)
		{"HTTPS://GitHub.com/Org/Repo.GIT", "github.com/org/repo"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeRepository, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, repository) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeDatabaseEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// mongodb+srv with credentials and query params
		{"mongodb+srv://user:pass@cluster.mongodb.net/db?retryWrites=true", "cluster.mongodb.net/db"},
		// redis protocol stripped
		{"redis://localhost:6379", "localhost:6379"},
		// rediss (TLS) protocol stripped
		{"rediss://cache.example.com", "cache.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeDatabase, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, database) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeStorageEdgeCases(t *testing.T) {
	tests := []struct {
		input   string
		subType string
		want    string
	}{
		// Regional S3 endpoint
		{"my-bucket.s3.us-west-2.amazonaws.com", "s3_bucket", "my-bucket"},
		// Path-style URL with object key — strip the key
		{"s3.amazonaws.com/my-bucket/key", "s3_bucket", "my-bucket"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeStorage, tt.subType)
			if got != tt.want {
				t.Errorf("NormalizeName(%q, storage/%s) = %q, want %q", tt.input, tt.subType, got, tt.want)
			}
		})
	}
}

func TestNormalizeIPEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// IPv4-mapped IPv6 → IPv4
		{"::ffff:192.168.1.1", "192.168.1.1"},
		// Brackets + port stripped for IPv6
		{"[2001:db8::1]:8080", "2001:db8::1"},
		// /32 CIDR stripped
		{"192.168.1.1/32", "192.168.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeIPAddress, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, ip_address) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeNetworkEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Already canonical
		{"10.0.0.0/8", "10.0.0.0/8"},
		// IPv6 CIDR
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeNetwork, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, network) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeCertEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Mixed case fingerprint with colons → all lowercase no colons
		{"AB:cd:EF:01:23:45:67:89:AB:cd:EF:01:23:45:67:89:AB:cd:EF:01:23:45:67:89:AB:cd:EF:01:23:45:67:89",
			"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeCertificate, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, certificate) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", ""},
		{"spaces only", "   ", ""},
		{"tab and newline", "\t\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test across multiple types
			for _, at := range []AssetType{AssetTypeDomain, AssetTypeIPAddress, AssetTypeRepository, AssetTypeApplication} {
				got := NormalizeName(tt.input, at, "")
				if got != tt.want {
					t.Errorf("NormalizeName(%q, %s) = %q, want %q", tt.input, at, got, tt.want)
				}
			}
		})
	}
}

func TestNormalizePreservesIdentity(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// ARN is case-sensitive — preserve case, only trim
		{"arn unchanged", "arn:aws:iam::123456:user/Admin", "arn:aws:iam::123456:user/Admin"},
		// Whitespace trimmed but case preserved
		{"arn trimmed", "  arn:aws:iam::123:role/MyRole  ", "arn:aws:iam::123:role/MyRole"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeName(tt.input, AssetTypeIdentity, "")
			if got != tt.want {
				t.Errorf("NormalizeName(%q, identity) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeIsFingerprint(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abcdef0123456789abcdef0123456789abcdef01", true},          // SHA1 (40 chars)
		{"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01", false}, // too long
		{"sha256abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", true},    // SHA256 with prefix
		{"not-a-fingerprint", false},
		{"ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01", true}, // SHA1 with colons
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isFingerprint(tt.input)
			if got != tt.want {
				t.Errorf("isFingerprint(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

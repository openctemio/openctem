# RFC-001 Appendix: Edge Cases per Asset Type

> **Status**: Completed — Part of [RFC-001](RFC-001-asset-identity-resolution.md)

Tài liệu này liệt kê TẤT CẢ edge cases có thể gặp khi dedup mỗi asset type.
Mỗi case có: scenario, input, expected behavior, và normalization rule.

---

## 1. DOMAIN

### Naming pattern: `example.com`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| D1 | Case variation | `example.com` | `Example.COM` | YES | `lowercase` |
| D2 | Trailing dot (FQDN) | `example.com` | `example.com.` | YES | `trim trailing dot` |
| D3 | Leading dot | `.example.com` | `example.com` | YES | `trim leading dot` |
| D4 | Whitespace | `example.com` | ` example.com ` | YES | `trim whitespace` |
| D5 | Punycode vs Unicode | `xn--nxasmq6b.com` | `ψαράδειγμα.com` | YES | `convert to punycode` (Phase 3) |
| D6 | With/without www | `www.example.com` | `example.com` | **NO** | Different assets — www is a subdomain |
| D7 | Subdomain sent as domain | `api.example.com` (type=domain) | `api.example.com` (type=subdomain) | **DEPENDS** | Same name but different type → different asset. Type should be corrected at ingest |
| D8 | With port | `example.com:443` | `example.com` | **NO** | Port is part of identity for services, not domains. Strip port from domain type |
| D9 | With protocol | `https://example.com` | `example.com` | YES (for domain type) | Strip protocol for domain assets |
| D10 | Wildcard | `*.example.com` | `example.com` | **NO** | Wildcard is a pattern, not a concrete domain |
| D11 | IP as domain | `192.168.1.1` (type=domain) | — | **WRONG TYPE** | Should be `ip_address`, not domain. Validate at ingest |
| D12 | With path | `example.com/path` | `example.com` | YES (for domain type) | Strip path for domain assets |

**Normalization function:**
```go
func normalizeDomainName(name string) string {
    name = strings.TrimSpace(name)
    name = strings.ToLower(name)
    name = strings.TrimRight(name, ".")
    name = strings.TrimLeft(name, ".")
    // Strip protocol if accidentally included
    name = stripProtocol(name)
    // Strip port if accidentally included
    if host, _, err := net.SplitHostPort(name); err == nil {
        name = host
    }
    // Strip path if accidentally included
    if idx := strings.Index(name, "/"); idx > 0 {
        name = name[:idx]
    }
    return name
}
```

---

## 2. SUBDOMAIN

### Naming pattern: `api.example.com`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| S1 | Case variation | `api.example.com` | `API.EXAMPLE.COM` | YES | `lowercase` |
| S2 | Trailing dot | `api.example.com.` | `api.example.com` | YES | `trim trailing dot` |
| S3 | Deep subdomain | `a.b.c.example.com` | `a.b.c.example.com` | YES | Exact match after normalize |
| S4 | With protocol | `https://api.example.com` | `api.example.com` | YES | Strip protocol |
| S5 | With port | `api.example.com:8443` | `api.example.com` | **DEPENDS** | For subdomain type, strip port. Port belongs to service |
| S6 | With path | `api.example.com/v1` | `api.example.com` | YES (subdomain) | Strip path |
| S7 | Root domain as subdomain | `example.com` (type=subdomain) | — | **WRONG LEVEL** | Should be `domain`. Detect: no dots before TLD |
| S8 | Wildcard subdomain | `*.api.example.com` | `api.example.com` | **NO** | Wildcard pattern vs concrete subdomain |
| S9 | Underscore subdomain | `_dmarc.example.com` | `_DMARC.example.com` | YES | Valid DNS, lowercase |
| S10 | Very long subdomain | 253+ chars | — | TRUNCATE | DNS max is 253 chars total |

**Normalization**: Same as domain (`normalizeDNSName`).

---

## 3. CERTIFICATE

### Naming pattern: Subject CN, serial, or fingerprint (varies by tool)

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| C1 | CN vs fingerprint as name | `*.example.com` (CN) | `sha256:abc123...` (fingerprint) | **MAYBE** | Correlate by fingerprint in properties |
| C2 | CN vs serial as name | `*.example.com` | `serial:1234567890` | **MAYBE** | Correlate by serial in properties |
| C3 | Same CN, different certs | `*.example.com` (cert A) | `*.example.com` (cert B, renewed) | **NO** | Different fingerprints = different certs |
| C4 | Wildcard CN case | `*.Example.COM` | `*.example.com` | YES | Lowercase |
| C5 | CN with trailing dot | `example.com.` | `example.com` | YES | Trim dot |
| C6 | Self-signed same CN | `localhost` (self-signed A) | `localhost` (self-signed B) | **NO** | Different fingerprints |
| C7 | SAN-only cert (no CN) | No CN, SAN=`api.example.com` | — | Name should be first SAN | Use SAN[0] as name if CN empty |
| C8 | Multi-domain cert | CN=`example.com`, SAN=[`example.com`, `www.example.com`] | — | 1 cert asset | SANs stored in properties |
| C9 | Fingerprint format | `SHA256:AB:CD:EF...` | `sha256:abcdef...` | YES | Normalize: lowercase, remove colons |
| C10 | Expired vs renewed | Same CN, old cert expired | New cert issued | **NO** | Different fingerprint → different asset |

**Correlation strategy:**
```
Primary key:   normalized name (CN or SAN[0])
Correlation:   properties.fingerprint (unique per cert)
               properties.serial_number (unique per issuer)

IF same name BUT different fingerprint → different asset (add suffix or use fingerprint as name)
IF different name BUT same fingerprint → MERGE (same cert, different naming)
```

**Normalization function:**
```go
func normalizeCertName(name string) string {
    name = strings.TrimSpace(name)
    name = strings.ToLower(name)
    name = strings.TrimRight(name, ".")
    // If name looks like a fingerprint, normalize format
    if isFingerprint(name) {
        name = normalizeFingerprint(name) // lowercase, remove colons/spaces
    }
    return name
}
```

---

## 4. IP_ADDRESS

### Naming pattern: `192.168.1.1` or `2001:db8::1`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| I1 | IPv4 leading zeros | `192.168.001.010` | `192.168.1.10` | YES | `net.ParseIP` canonical |
| I2 | IPv6 full vs short | `2001:0db8:0000:0000:0000:0000:0000:0001` | `2001:db8::1` | YES | `net.ParseIP` canonical |
| I3 | IPv6 mixed notation | `::ffff:192.168.1.1` | `192.168.1.1` | **DEPENDS** | Same host, but v4-mapped v6 is different address. Treat as same? Recommend: YES, normalize v4-mapped to v4 |
| I4 | IPv6 zone ID | `fe80::1%eth0` | `fe80::1` | YES | Strip zone ID (`%...`) — zone is interface-local |
| I5 | IPv4 integer form | `3232235777` (=192.168.1.1) | `192.168.1.1` | YES | Convert integer to dotted (Phase 3) |
| I6 | IPv4 hex form | `0xC0A80101` | `192.168.1.1` | YES | Convert hex to dotted (Phase 3) |
| I7 | Loopback variations | `127.0.0.1` | `localhost` | **NO** | Different types (IP vs hostname) |
| I8 | With port | `192.168.1.1:443` | `192.168.1.1` | YES (for ip_address type) | Strip port |
| I9 | With CIDR | `192.168.1.1/32` | `192.168.1.1` | YES | Strip /32 (single host CIDR) |
| I10 | With protocol | `https://192.168.1.1` | `192.168.1.1` | YES (for ip_address type) | Strip protocol |
| I11 | Private vs public same IP | `10.0.0.1` (tenant A) | `10.0.0.1` (tenant B) | **NO** | Tenant isolation — same IP different tenants |
| I12 | Brackets (IPv6 URL) | `[2001:db8::1]` | `2001:db8::1` | YES | Strip brackets |

**Normalization function:**
```go
func normalizeIPAddress(name string) string {
    name = strings.TrimSpace(name)
    // Strip brackets [IPv6]
    name = strings.Trim(name, "[]")
    // Strip protocol
    name = stripProtocol(name)
    // Strip port
    if host, _, err := net.SplitHostPort(name); err == nil {
        name = host
    }
    // Strip CIDR /32 or /128
    if strings.HasSuffix(name, "/32") || strings.HasSuffix(name, "/128") {
        name = name[:strings.LastIndex(name, "/")]
    }
    // Strip zone ID
    if idx := strings.Index(name, "%"); idx > 0 {
        name = name[:idx]
    }
    // Canonical form via net.ParseIP
    ip := net.ParseIP(name)
    if ip == nil {
        return name
    }
    // Normalize IPv4-mapped IPv6 to IPv4
    if v4 := ip.To4(); v4 != nil {
        return v4.String()
    }
    return ip.String()
}
```

---

## 5. HOST

### Naming pattern: hostname OR IP (most complex type)

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| H1 | Hostname vs IP | `web-server-01` | `192.168.1.10` (same host) | YES | IP correlation |
| H2 | FQDN vs short name | `web-01.corp.local` | `web-01` | **MAYBE** | Correlate by IP. If same IP → merge, rename to FQDN |
| H3 | Case variation | `Web-Server-01` | `web-server-01` | YES | Lowercase |
| H4 | Trailing dot | `server.corp.local.` | `server.corp.local` | YES | Trim dot |
| H5 | Multiple IPs same host | `web-01` (IP=[.1,.2,.3]) | Splunk sends `.2` only | YES | Any IP match → same host |
| H6 | IP reuse (DHCP) | `web-01` had `10.0.0.5` last week | `db-01` has `10.0.0.5` now | **NO** | Check `last_seen` staleness (>30d → don't merge) |
| H7 | Same IP different tenants | `10.0.0.1` (tenant A) | `10.0.0.1` (tenant B) | **NO** | Tenant isolation |
| H8 | NAT shared IP | Host A internal `10.0.0.1` → NAT `203.0.113.1` | Host B internal `10.0.0.2` → NAT `203.0.113.1` | **NO** | Correlate on private IPs only, not public behind NAT |
| H9 | VM migration (new IP) | `vm-prod-01` had `10.0.0.5` | Same VM now `10.0.0.50` (migrated) | YES | Same hostname → same asset (name match) |
| H10 | Container host vs VM | `k8s-node-01` (bare metal) | `k8s-node-01` (VM) | YES | Same hostname = same entity regardless |
| H11 | IPv6 host | Host named `2001:db8::1` | Host named `2001:0db8::0001` | YES | IPv6 canonical |
| H12 | Hostname = IP | `192.168.1.10` (type=host) | `192.168.1.10` (type=ip_address) | **NO** | Different asset types |
| H13 | Nessus FQDN override | Nessus `host-fqdn=server.corp` | Name attribute=`192.168.1.10` | YES | FQDN wins, IP in properties |
| H14 | Cloud instance ID | AWS `i-0abc123` | Hostname `ip-10-0-0-5.ec2.internal` | **MAYBE** | Correlate by `external_id` if set |
| H15 | Dual-stack host | IPv4 `192.168.1.10` | IPv6 `2001:db8::10` | YES if same host | Both in `ip_addresses[]` → match |
| H16 | Hostname with domain search | `server01` (short) | `server01.corp.local` (resolved) | **MAYBE** | Correlate by IP. Name alone → ambiguous |
| H17 | Reverse DNS mismatch | Forward: `web.example.com` → `1.2.3.4` | Reverse: `1.2.3.4` → `host-1-2-3-4.isp.net` | YES | Same IP → merge, keep forward DNS name |
| H18 | Hostname rename | Was `web-01`, renamed to `api-gateway-01` | Same IPs | YES | IP match → merge/rename |

**Sub_type edge cases:**

| # | Edge Case | Sub Type | Rule |
|---|---|---|---|
| H19 | EC2 instance | `compute` | Correlate by `external_id` (instance ID) |
| H20 | Lambda function | `serverless` | Name = function name. No IP correlation (no static IP) |
| H21 | Fargate task | `compute` | Correlate by task ID, ephemeral IPs → don't use IP |

**Correlation priority:**
```
1. Exact name match (after normalize)
2. IP match via ip_addresses[] array
3. Hostname match via properties.hostname
4. external_id match (cloud instance ID)
5. No match → create new
```

---

## 6. SERVICE

### Naming pattern: varies by sub_type

#### sub_type: `open_port`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| SP1 | Format variation | `192.168.1.10:443/tcp` | `192.168.1.10:443:tcp` | YES | Normalize separator |
| SP2 | Missing protocol | `192.168.1.10:443` | `192.168.1.10:443:tcp` | YES | Default to `tcp` |
| SP3 | UDP vs TCP same port | `192.168.1.10:53:tcp` | `192.168.1.10:53:udp` | **NO** | Different protocols = different services |
| SP4 | Hostname vs IP | `web-01:443:tcp` | `192.168.1.10:443:tcp` | **MAYBE** | Correlate parent host by IP |
| SP5 | IPv6 port | `[2001:db8::1]:443:tcp` | `2001:db8::1:443:tcp` | YES | Normalize IPv6+port format |
| SP6 | Port 0 | `192.168.1.10:0:tcp` | — | INVALID | Reject port 0 |
| SP7 | Port > 65535 | `192.168.1.10:99999` | — | INVALID | Reject out of range |

#### sub_type: `http`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| SH1 | HTTP vs HTTPS | `http://api.example.com` | `https://api.example.com` | **NO** | Different protocol = different service |
| SH2 | Default port | `https://api.example.com:443` | `https://api.example.com` | YES | Strip default ports |
| SH3 | Non-default port | `https://api.example.com:8443` | `https://api.example.com` | **NO** | Different port = different service |
| SH4 | Trailing slash | `https://api.example.com/` | `https://api.example.com` | YES | Strip trailing slash |
| SH5 | Case in host | `https://API.Example.COM` | `https://api.example.com` | YES | Lowercase host |
| SH6 | Path included | `https://api.example.com/v1` | `https://api.example.com` | **NO** | Different path = different service (for http sub_type, keep base URL) |
| SH7 | With query string | `https://api.example.com?v=1` | `https://api.example.com` | YES | Strip query for service identity |

#### sub_type: `discovered_url`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| SU1 | Query string variation | `https://app.com/login?ref=1` | `https://app.com/login?ref=2` | YES | Strip query params |
| SU2 | Fragment variation | `https://app.com/page#section1` | `https://app.com/page#section2` | YES | Strip fragment |
| SU3 | Trailing slash | `https://app.com/login/` | `https://app.com/login` | YES | Strip trailing slash |
| SU4 | Double slash in path | `https://app.com//login` | `https://app.com/login` | YES | Normalize path slashes |
| SU5 | URL encoding | `https://app.com/path%20with%20spaces` | `https://app.com/path with spaces` | YES | Decode %XX then re-encode canonical |
| SU6 | Case in path | `https://app.com/Login` | `https://app.com/login` | **DEPENDS** | Paths CAN be case-sensitive (server-dependent). Default: keep case, lowercase host only |

---

## 7. APPLICATION

### Naming pattern: URL or app name

#### sub_type: `website`, `web_application`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| A1 | Protocol variation | `https://app.example.com` | `http://app.example.com` | **DEPENDS** | If same content → YES. Default: treat as same for web apps (protocol upgrade is common) |
| A2 | WWW prefix | `https://www.example.com` | `https://example.com` | **DEPENDS** | Usually same app, but could be different. Default: treat as different (www is a subdomain) |
| A3 | Default port | `https://app.example.com:443` | `https://app.example.com` | YES | Strip default port |
| A4 | With path | `https://app.example.com/app` | `https://app.example.com` | **NO** | Different paths = could be different apps |
| A5 | Case | `https://APP.Example.COM` | `https://app.example.com` | YES | Lowercase host |
| A6 | Trailing slash | `https://app.example.com/` | `https://app.example.com` | YES | Strip |

#### sub_type: `api`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| AA1 | Version in path | `https://api.example.com/v1` | `https://api.example.com/v2` | **NO** | Different API versions = different assets |
| AA2 | Base URL vs endpoint | `https://api.example.com` | `https://api.example.com/users` | **NO** | Base API vs specific endpoint |
| AA3 | REST vs GraphQL | `https://api.example.com/graphql` | `https://api.example.com/rest` | **NO** | Different APIs on same host |

#### sub_type: `mobile_app`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| AM1 | Bundle ID case | `com.Company.App` | `com.company.app` | YES | Lowercase (iOS/Android are case-insensitive) |
| AM2 | Platform variation | `com.company.app` (iOS) | `com.company.app` (Android) | **DEPENDS** | Same bundle = usually same app, different platform. Treat as same asset, store platform in properties |
| AM3 | Version in name | `com.company.app.v2` | `com.company.app` | **NO** | Different apps (v2 is separate bundle) |

---

## 8. REPOSITORY

### Naming pattern: URL or org/repo

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| R1 | HTTPS vs SSH | `https://github.com/org/repo` | `git@github.com:org/repo.git` | YES | Normalize to `github.com/org/repo` |
| R2 | With .git | `github.com/org/repo.git` | `github.com/org/repo` | YES | Strip `.git` |
| R3 | Case variation | `github.com/Org/Repo` | `github.com/org/repo` | YES | Lowercase |
| R4 | Different platforms | `github.com/org/repo` | `gitlab.com/org/repo` | **NO** | Different platforms = different repos |
| R5 | Without host | `org/repo` | `github.com/org/repo` | **MAYBE** | Correlate via integration URL |
| R6 | Bare name | `repo` | `github.com/org/repo` | **MAYBE** | Fuzzy match (low confidence) |
| R7 | Repo transferred | `github.com/old-org/repo` | `github.com/new-org/repo` | **MAYBE** | GitHub redirects, but different names. Correlate by `external_id` (repo ID) |
| R8 | Repo renamed | `github.com/org/old-name` | `github.com/org/new-name` | **MAYBE** | Correlate by `external_id` (repo ID persists across renames) |
| R9 | Fork | `github.com/org/repo` | `github.com/fork-org/repo` | **NO** | Different orgs = different repos (even if forked) |
| R10 | Monorepo subpath | `github.com/org/monorepo` | `github.com/org/monorepo/packages/lib` | **NO** | Subpath = different scope, but same repo |
| R11 | Self-hosted GitLab | `gitlab.internal.company.com/org/repo` | `org/repo` (from CI) | **MAYBE** | Correlate via integration URL |
| R12 | Azure DevOps format | `dev.azure.com/org/project/_git/repo` | `org/project/repo` | YES | Normalize Azure format |
| R13 | Bitbucket format | `bitbucket.org/org/repo` | `org/repo` | **MAYBE** | Correlate via integration |
| R14 | Trailing slash | `github.com/org/repo/` | `github.com/org/repo` | YES | Strip trailing slash |
| R15 | With branch ref | `github.com/org/repo/tree/main` | `github.com/org/repo` | YES | Strip branch path |

**Normalization function update:**
```go
func normalizeRepoName(name string) string {
    name = strings.TrimSpace(name)
    name = strings.TrimPrefix(name, "https://")
    name = strings.TrimPrefix(name, "http://")
    
    // SSH format: git@host:path → host/path
    if strings.HasPrefix(name, "git@") {
        name = strings.TrimPrefix(name, "git@")
        if idx := strings.Index(name, ":"); idx > 0 {
            name = name[:idx] + "/" + name[idx+1:]
        }
    }
    
    name = strings.TrimSuffix(name, ".git")
    name = strings.ToLower(name)
    name = strings.TrimRight(name, "/")
    
    // Strip Azure DevOps _git segment
    // dev.azure.com/org/project/_git/repo → dev.azure.com/org/project/repo
    name = strings.Replace(name, "/_git/", "/", 1)
    
    // Strip branch references: /tree/main, /blob/main, /commit/abc
    for _, ref := range []string{"/tree/", "/blob/", "/commit/", "/branches/"} {
        if idx := strings.Index(name, ref); idx > 0 {
            name = name[:idx]
        }
    }
    
    return name
}
```

---

## 9. CLOUD_ACCOUNT

### Naming pattern: account alias or account ID

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| CA1 | Alias vs ID | `prod-account` (alias) | `123456789012` (AWS account ID) | YES | Correlate by `external_id` |
| CA2 | ARN format | `arn:aws:organizations::123456789012:account` | `123456789012` | YES | Extract account ID from ARN |
| CA3 | Azure subscription | `my-subscription` | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (subscription ID) | YES | Correlate by `external_id` |
| CA4 | GCP project | `my-project` | `my-project-123456` (project number) | YES | Correlate by `external_id` |
| CA5 | Case variation | `Prod-Account` | `prod-account` | YES | Lowercase |
| CA6 | Multi-region same account | `123456789012` (us-east-1) | `123456789012` (eu-west-1) | YES | Same account, different regions. 1 asset |
| CA7 | Root vs member account | `123456789012` (root) | `123456789012` (member, same ID) | YES | Same account |
| CA8 | Cross-cloud same name | AWS `prod-account` | Azure `prod-account` | **NO** | Different cloud providers. Store provider in properties |

---

## 10. STORAGE

### Naming pattern: bucket name or URL

#### sub_type: `s3_bucket`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| ST1 | With s3:// prefix | `s3://my-bucket` | `my-bucket` | YES | Strip `s3://` |
| ST2 | With URL format | `my-bucket.s3.amazonaws.com` | `my-bucket` | YES | Extract bucket name |
| ST3 | Path-style URL | `s3.amazonaws.com/my-bucket` | `my-bucket` | YES | Extract bucket name |
| ST4 | Regional endpoint | `my-bucket.s3.us-east-1.amazonaws.com` | `my-bucket` | YES | Strip region/domain |
| ST5 | Case | S3 buckets are lowercase-only by AWS rule | — | Already lowercase | No action needed |

#### sub_type: `container_registry`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| SR1 | With/without tag | `registry.io/org/image:latest` | `registry.io/org/image` | YES | Strip tag for registry identity |
| SR2 | With digest | `registry.io/org/image@sha256:abc` | `registry.io/org/image` | YES | Strip digest |
| SR3 | Docker Hub implicit | `nginx` | `docker.io/library/nginx` | YES | Expand Docker Hub short name |
| SR4 | Case | `Registry.IO/Org/Image` | `registry.io/org/image` | YES | Lowercase |
| SR5 | Port in registry | `registry.internal:5000/org/image` | `registry.internal/org/image` | **NO** | Different port = potentially different registry |

---

## 11. CONTAINER

### Naming pattern: container name, image, or ID

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| CT1 | Short vs full SHA | `abc123def456` (12 chars) | `abc123def456789...` (64 chars) | YES | If short is prefix of full → same |
| CT2 | Name vs ID | `my-container` (name) | `abc123...` (ID) | **MAYBE** | Correlate by container ID in properties |
| CT3 | Kubernetes pod name | `my-app-7d8f9-abc12` | `my-app-7d8f9-xyz99` | **NO** | Different pod instances (random suffix) |
| CT4 | Deployment name | `my-app` (deployment) | `my-app-7d8f9-abc12` (pod) | **NO** | Different concepts (deployment vs pod) |
| CT5 | Same image different container | Container A from `nginx:latest` | Container B from `nginx:latest` | **NO** | Same image but different container instances |
| CT6 | Case | `My-Container` | `my-container` | YES | Lowercase |
| CT7 | With namespace prefix | `default/my-app` | `my-app` | **MAYBE** | If same cluster, `default/my-app` is more specific |

---

## 12. KUBERNETES

### Naming pattern: cluster name or namespace path

#### sub_type: `cluster`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| K1 | Case | `Prod-Cluster` | `prod-cluster` | YES | Lowercase |
| K2 | Cloud ARN vs name | `arn:aws:eks:us-east-1:123:cluster/prod` | `prod` | YES | Correlate by `external_id` |
| K3 | Context name vs cluster | `arn:aws:eks:...` (kubeconfig context) | `prod-cluster` (cluster name) | **MAYBE** | Context ≠ cluster name. Normalize to cluster name |
| K4 | Same name different clouds | `prod` (EKS) | `prod` (GKE) | **NO** | Different providers. Store provider in properties |

#### sub_type: `namespace`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| KN1 | With cluster prefix | `prod-cluster/kube-system` | `kube-system` | **DEPENDS** | Without cluster prefix → ambiguous. Recommend always include cluster |
| KN2 | Case | `Kube-System` | `kube-system` | YES | K8s namespaces are lowercase by spec |
| KN3 | Same namespace different clusters | `prod-cluster/default` | `staging-cluster/default` | **NO** | Different clusters |

---

## 13. DATABASE

### Naming pattern: connection string, hostname:port/dbname, or name

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| DB1 | Connection string vs name | `postgres://db.example.com:5432/mydb` | `mydb` | **MAYBE** | Correlate by hostname:port |
| DB2 | Hostname vs IP | `db.example.com:5432` | `192.168.1.50:5432` | **MAYBE** | Correlate by IP (same as host) |
| DB3 | With/without port | `db.example.com:5432` | `db.example.com` | **DEPENDS** | Default port can be implied. Recommend: always include port |
| DB4 | With/without dbname | `db.example.com:5432/mydb` | `db.example.com:5432/otherdb` | **NO** | Different databases on same server |
| DB5 | Protocol prefix | `postgres://host:5432/db` | `host:5432/db` | YES | Strip protocol |
| DB6 | Case | `DB.Example.COM` | `db.example.com` | YES | Lowercase host |
| DB7 | With credentials | `postgres://user:pass@host:5432/db` | `host:5432/db` | YES | Strip credentials! (security) |
| DB8 | RDS endpoint | `mydb.abc123.us-east-1.rds.amazonaws.com` | `mydb` | **MAYBE** | Correlate by `external_id` |
| DB9 | Read replica | `mydb-replica.abc123.rds.amazonaws.com` | `mydb.abc123.rds.amazonaws.com` | **NO** | Different endpoints, different assets |

**Normalization function:**
```go
func normalizeDatabaseName(name string) string {
    name = strings.TrimSpace(name)
    // Strip protocol
    for _, proto := range []string{"postgres://", "postgresql://", "mysql://", "mongodb://", "redis://"} {
        name = strings.TrimPrefix(name, proto)
    }
    // Strip credentials (user:pass@)
    if atIdx := strings.Index(name, "@"); atIdx > 0 {
        name = name[atIdx+1:]
    }
    // Lowercase host part
    name = strings.ToLower(name)
    // Strip query params
    if qIdx := strings.Index(name, "?"); qIdx > 0 {
        name = name[:qIdx]
    }
    return name
}
```

---

## 14. NETWORK

### Naming pattern: CIDR, VPC ID, or name

#### sub_type: (none), `vpc`, `subnet`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| N1 | CIDR format | `192.168.1.0/24` | `192.168.1.0/24` | YES | Exact match after normalize |
| N2 | Non-canonical CIDR | `192.168.1.100/24` | `192.168.1.0/24` | YES | Normalize to network address (`net.ParseCIDR` zeroes host bits) |
| N3 | VPC ID format | `vpc-abc123` | `VPC-ABC123` | YES | Lowercase |
| N4 | VPC name vs ID | `prod-vpc` (name) | `vpc-abc123` (ID) | **MAYBE** | Correlate by `external_id` |
| N5 | Same CIDR different VPCs | `10.0.0.0/16` (VPC A) | `10.0.0.0/16` (VPC B) | **NO** | Need VPC context. Store VPC in properties |
| N6 | IPv6 CIDR | `2001:db8::/32` | `2001:0db8:0000::/32` | YES | Normalize IPv6 prefix |

#### sub_type: `firewall`, `load_balancer`

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| NF1 | Cloud resource ARN | `arn:aws:elasticloadbalancing:...` | `my-alb` | **MAYBE** | Correlate by `external_id` |
| NF2 | Case | `Prod-Firewall` | `prod-firewall` | YES | Lowercase |

**Normalization function:**
```go
func normalizeNetworkName(name string, subType string) string {
    name = strings.TrimSpace(name)
    name = strings.ToLower(name)
    // CIDR normalization
    if subType == "subnet" || subType == "" {
        if _, network, err := net.ParseCIDR(name); err == nil {
            return network.String() // Canonical CIDR (zeroed host bits)
        }
    }
    return name
}
```

---

## 15. IDENTITY

### Naming pattern: username, ARN, or email

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| ID1 | Username vs ARN | `admin` | `arn:aws:iam::123:user/admin` | YES | Correlate by `external_id` (ARN) |
| ID2 | ARN case | ARN is case-sensitive in AWS | — | Keep exact case for ARN | BUT username part can be matched case-insensitively |
| ID3 | Email vs username | `admin@company.com` | `admin` | **MAYBE** | Correlate if same provider |
| ID4 | Service account email | `sa@project.iam.gserviceaccount.com` | `sa` | **MAYBE** | Correlate by `external_id` |
| ID5 | Cross-account same name | AWS account A `admin` | AWS account B `admin` | **NO** | Different accounts. Store account in properties |
| ID6 | Role vs user same name | IAM role `admin` | IAM user `admin` | **NO** | Different sub_types |
| ID7 | Assumed role session | `arn:aws:sts::123:assumed-role/admin/session` | `arn:aws:iam::123:role/admin` | YES | Normalize assumed-role to base role ARN |
| ID8 | GCP vs AWS same name | GCP SA `admin` | AWS user `admin` | **NO** | Different providers |

---

## 16. UNCLASSIFIED

### Naming pattern: anything

| # | Edge Case | Input A | Input B | Same entity? | Rule |
|---|---|---|---|---|---|
| U1 | Whitespace | ` asset name ` | `asset name` | YES | Trim |
| U2 | Case | `My Asset` | `my asset` | **DEPENDS** | Unclassified → play safe, keep case (could be anything) |
| U3 | Null bytes | `name\x00injected` | `name` | YES | Strip null bytes (already done) |

---

## Cross-Cutting Edge Cases (ALL types)

| # | Edge Case | All Types | Rule |
|---|---|---|---|
| X1 | Unicode normalization | `café` (NFC) vs `café` (NFD) | Normalize to NFC form |
| X2 | Zero-width chars | `exam​ple.com` (zero-width space) | Strip zero-width characters |
| X3 | Homoglyph attack | `exаmple.com` (Cyrillic 'а') | Detect punycode (Phase 3, security feature) |
| X4 | Very long name | 10000+ chars | Truncate to MaxAssetNameLength (500) |
| X5 | Empty after normalize | `...` → normalize → `` | Reject — name required |
| X6 | Same name different type | `example.com` (domain) | `example.com` (host) | **NO** | Different types = different assets (unique constraint should include type?) |
| X7 | Tab/newline in name | `name\twith\ttabs` | `name with tabs` | YES | Replace control chars with space, then trim |
| X8 | SQL injection in name | `'; DROP TABLE assets; --` | — | Parameterized queries handle this. sanitizeAssetName removes `'` and `;` |

### X6 Deep Dive: Same name, different asset type

Currently unique constraint is `(tenant_id, name)` — does NOT include `asset_type`. This means:

```
INSERT domain "example.com"   → OK
INSERT host   "example.com"   → CONFLICT! Same name.
```

**Is this correct?** It depends:
- `example.com` as domain AND as host is the same entity (a server hosting that domain)
- But they have different properties and different semantic meaning

**Recommendation**: Keep current behavior (`name` unique per tenant regardless of type). If same name appears as different type, it's likely the same entity viewed differently. The `asset_type` can be updated/promoted if needed.

**Exception**: `ip_address` type `192.168.1.1` and `host` type `192.168.1.1` — these SHOULD be the same entity. The type should be `host` (more specific), with IP stored in properties.

---

## Summary: Normalization Rules per Type

```go
func NormalizeName(name string, assetType AssetType, subType string) string {
    // Common: trim, strip null bytes, strip zero-width chars
    name = commonNormalize(name)
    if name == "" {
        return ""
    }

    switch assetType {
    case AssetTypeDomain, AssetTypeSubdomain:
        return normalizeDNSName(name)

    case AssetTypeIPAddress:
        return normalizeIPAddress(name)

    case AssetTypeHost:
        return normalizeHostName(name)

    case AssetTypeService:
        return normalizeServiceName(name, subType)

    case AssetTypeApplication:
        return normalizeApplicationName(name, subType)

    case AssetTypeRepository:
        return normalizeRepoName(name)

    case AssetTypeCertificate:
        return normalizeCertName(name)

    case AssetTypeCloudAccount:
        return strings.ToLower(strings.TrimSpace(name))

    case AssetTypeStorage:
        return normalizeStorageName(name, subType)

    case AssetTypeContainer:
        return strings.ToLower(strings.TrimSpace(name))

    case AssetTypeKubernetes:
        return strings.ToLower(strings.TrimSpace(name))

    case AssetTypeDatabase:
        return normalizeDatabaseName(name)

    case AssetTypeNetwork:
        return normalizeNetworkName(name, subType)

    case AssetTypeIdentity:
        return strings.TrimSpace(name) // Keep case (ARN is case-sensitive)

    default:
        return strings.TrimSpace(name)
    }
}
```

---

## Total Edge Cases Count

| Type | Edge Cases | Priority |
|---|---|---|
| Domain | 12 | HIGH |
| Subdomain | 10 | HIGH |
| Certificate | 10 | HIGH |
| IP Address | 12 | MEDIUM |
| Host | 18 + 3 sub_type = 21 | VERY HIGH |
| Service | 7 + 7 + 6 = 20 | HIGH |
| Application | 6 + 3 + 3 = 12 | HIGH |
| Repository | 15 | VERY HIGH |
| Cloud Account | 8 | HIGH |
| Storage | 5 + 5 = 10 | MEDIUM |
| Container | 7 | MEDIUM |
| Kubernetes | 4 + 3 = 7 | MEDIUM |
| Database | 9 | MEDIUM |
| Network | 6 + 2 = 8 | LOW |
| Identity | 8 | HIGH |
| Unclassified | 3 | LOW |
| Cross-cutting | 8 | HIGH |
| **TOTAL** | **170** | |

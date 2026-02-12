# Asset Properties Schema Documentation

This document defines the JSON schema for the `properties` JSONB field in the `assets` table.
The schema varies by `asset_type` - each type has specific properties relevant to that asset category.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              assets table                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ id, tenant_id, name, asset_type, criticality, status, ...                   │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ properties JSONB - Type-specific data (varies by asset_type)            │ │
│ │ metadata JSONB   - Custom tags, labels, annotations                     │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
          Extension Tables    Cross-cutting    JSONB properties
          (complex types)       Tables         (simple types)
          ─────────────────   ─────────────   ─────────────────
          asset_repositories  asset_services  domain, ip_address,
          asset_branches      asset_state_    certificate, cloud_*,
                              history         network_*, iam_*, etc.
```

## Properties Schema by Asset Type

---

### Network & External Assets

#### `domain`
```json
{
  "registrar": "string",           // Domain registrar (e.g., "GoDaddy", "Cloudflare")
  "registered_at": "datetime",     // Registration date (ISO 8601)
  "expires_at": "datetime",        // Expiration date (ISO 8601)
  "nameservers": ["string"],       // List of nameservers
  "dns_records": [                 // DNS records
    {
      "type": "string",            // A, AAAA, CNAME, MX, TXT, NS, SOA
      "name": "string",            // Record name
      "value": "string",           // Record value
      "ttl": "integer"             // TTL in seconds
    }
  ],
  "whois": {                       // WHOIS data
    "registrant_name": "string",
    "registrant_org": "string",
    "registrant_email": "string",
    "admin_email": "string",
    "tech_email": "string"
  }
}
```

#### `subdomain`
```json
{
  "parent_domain": "string",       // Parent domain (e.g., "example.com")
  "resolved_ips": ["string"],      // Resolved IP addresses
  "cname_target": "string",        // CNAME target if applicable
  "discovery_source": "string",    // How it was discovered: dns_enum, cert_transparency, brute_force
  "is_wildcard": "boolean"         // Whether it's a wildcard subdomain
}
```

#### `ip_address`
```json
{
  "version": "integer",            // 4 or 6
  "hostname": "string",            // Reverse DNS hostname
  "asn": "integer",                // Autonomous System Number
  "asn_org": "string",             // ASN organization name
  "isp": "string",                 // Internet Service Provider
  "country": "string",             // ISO 3166-1 alpha-2 country code
  "city": "string",                // City name
  "geolocation": {
    "latitude": "number",
    "longitude": "number",
    "accuracy": "number"           // Accuracy in meters
  },
  "ports": [                       // Discovered open ports
    {
      "port": "integer",
      "protocol": "string",        // tcp, udp
      "state": "string",           // open, filtered, closed
      "service": "string",         // http, ssh, etc.
      "banner": "string",
      "version": "string"
    }
  ],
  "is_private": "boolean",         // RFC 1918 private IP
  "is_reserved": "boolean"         // Reserved/special IP
}
```

#### `certificate`
```json
{
  "serial_number": "string",       // Certificate serial number
  "subject_cn": "string",          // Subject Common Name
  "sans": ["string"],              // Subject Alternative Names
  "issuer_cn": "string",           // Issuer Common Name
  "issuer_org": "string",          // Issuer Organization
  "not_before": "datetime",        // Valid from (ISO 8601)
  "not_after": "datetime",         // Valid until (ISO 8601)
  "signature_algorithm": "string", // e.g., "SHA256-RSA"
  "key_algorithm": "string",       // e.g., "RSA", "ECDSA"
  "key_size": "integer",           // Key size in bits
  "fingerprint_sha256": "string",  // SHA-256 fingerprint
  "fingerprint_sha1": "string",    // SHA-1 fingerprint (deprecated)
  "is_self_signed": "boolean",
  "is_expired": "boolean",
  "is_wildcard": "boolean",
  "ct_logs": ["string"]            // Certificate Transparency logs
}
```

---

### Application Assets

#### `website` / `web_application`
```json
{
  "url": "string",                 // Primary URL
  "title": "string",               // Page title
  "technologies": ["string"],      // Detected technologies (Wappalyzer)
  "server": "string",              // Web server (nginx, Apache)
  "framework": "string",           // Web framework (React, Django)
  "cms": "string",                 // CMS if detected (WordPress, Drupal)
  "response_code": "integer",      // HTTP response code
  "content_type": "string",        // Content-Type header
  "headers": {                     // Security headers
    "x_frame_options": "string",
    "content_security_policy": "string",
    "strict_transport_security": "string",
    "x_content_type_options": "string",
    "x_xss_protection": "string"
  },
  "tls_version": "string",         // TLS 1.2, TLS 1.3
  "has_waf": "boolean",            // WAF detected
  "waf_vendor": "string"           // WAF vendor if detected
}
```

#### `api`
```json
{
  "base_url": "string",            // API base URL
  "api_type": "string",            // rest, graphql, grpc, soap, websocket
  "version": "string",             // API version
  "authentication": "string",      // none, api_key, oauth2, jwt, basic
  "documentation_url": "string",   // API docs URL (Swagger, etc.)
  "rate_limiting": "boolean",      // Rate limiting enabled
  "cors_enabled": "boolean",       // CORS enabled
  "endpoints_count": "integer"     // Number of discovered endpoints
}
```

#### `mobile_app`
```json
{
  "platform": "string",            // ios, android
  "package_name": "string",        // Bundle ID (iOS) or Package name (Android)
  "version": "string",             // App version
  "store_url": "string",           // App Store / Play Store URL
  "min_sdk_version": "string",     // Minimum SDK version
  "target_sdk_version": "string",  // Target SDK version
  "permissions": ["string"],       // Requested permissions
  "signing_certificate": "string", // Certificate fingerprint
  "uses_ssl_pinning": "boolean"    // SSL pinning detected
}
```

#### `service`
```json
{
  "name": "string",                // Service name
  "version": "string",             // Service version
  "port": "integer",               // Port number
  "protocol": "string",            // Application protocol: http, ssh, smtp, ftp, dns, ldap, smb, rdp, mysql, postgresql
  "transport": "string",           // Transport: tcp, udp
  "tls_enabled": "boolean",        // TLS/SSL enabled
  "tls_version": "string",         // TLS version
  "banner": "string",              // Service banner
  "product": "string",             // Product name (OpenSSH, nginx)
  "cpe": "string",                 // CPE identifier
  "state": "string",               // open, filtered, closed
  "auth_required": "boolean",      // Authentication required
  "auth_methods": ["string"],      // Supported auth methods
  "default_credentials": "boolean",// Default credentials detected
  "anonymous_access": "boolean",   // Anonymous access allowed
  "response_time_ms": "integer"    // Response time in ms
}
```

---

### Cloud Assets

#### `cloud_account`
```json
{
  "provider": "string",            // aws, gcp, azure, digitalocean
  "account_id": "string",          // AWS Account ID, GCP Project ID
  "account_name": "string",        // Account/project name
  "region": "string",              // Primary region
  "organization_id": "string",     // Organization ID if applicable
  "root_email": "string",          // Root account email
  "mfa_enabled": "boolean",        // MFA enabled on root
  "billing_enabled": "boolean"     // Billing configured
}
```

#### `compute`
```json
{
  "provider": "string",            // aws, gcp, azure
  "instance_id": "string",         // Instance ID
  "instance_type": "string",       // Instance type (t3.micro, n1-standard-1)
  "region": "string",              // Region
  "zone": "string",                // Availability zone
  "private_ip": "string",          // Private IP
  "public_ip": "string",           // Public IP (if any)
  "vpc_id": "string",              // VPC ID
  "subnet_id": "string",           // Subnet ID
  "security_groups": ["string"],   // Security group IDs
  "iam_role": "string",            // IAM role attached
  "state": "string",               // running, stopped, terminated
  "launch_time": "datetime",       // Launch timestamp
  "image_id": "string",            // AMI/Image ID
  "platform": "string",            // linux, windows
  "tags": {}                       // Resource tags
}
```

#### `storage` / `s3_bucket`
```json
{
  "provider": "string",            // aws, gcp, azure
  "bucket_name": "string",         // Bucket name
  "region": "string",              // Region
  "arn": "string",                 // Resource ARN
  "creation_date": "datetime",     // Creation date
  "versioning_enabled": "boolean", // Versioning enabled
  "encryption_enabled": "boolean", // Encryption at rest
  "encryption_type": "string",     // AES256, aws:kms
  "public_access": "string",       // public, private, restricted
  "acl": "string",                 // ACL setting
  "lifecycle_rules": "boolean",    // Lifecycle rules configured
  "logging_enabled": "boolean",    // Access logging enabled
  "website_enabled": "boolean",    // Static website hosting
  "cors_enabled": "boolean"        // CORS configured
}
```

#### `serverless`
```json
{
  "provider": "string",            // aws, gcp, azure
  "function_name": "string",       // Function name
  "runtime": "string",             // nodejs18.x, python3.11, go1.x
  "handler": "string",             // Handler path
  "memory_mb": "integer",          // Memory allocation
  "timeout_seconds": "integer",    // Timeout
  "region": "string",              // Region
  "arn": "string",                 // Function ARN
  "role": "string",                // Execution role
  "vpc_config": {                  // VPC configuration
    "vpc_id": "string",
    "subnet_ids": ["string"],
    "security_group_ids": ["string"]
  },
  "environment_variables": ["string"], // Env var names (not values!)
  "layers": ["string"],            // Layer ARNs
  "last_modified": "datetime"      // Last modification time
}
```

#### `container_registry`
```json
{
  "provider": "string",            // aws (ECR), gcp (GCR/AR), azure (ACR), dockerhub
  "registry_url": "string",        // Registry URL
  "repository_count": "integer",   // Number of repositories
  "image_count": "integer",        // Total images
  "scan_on_push": "boolean",       // Vulnerability scanning enabled
  "encryption_enabled": "boolean", // Encryption at rest
  "immutable_tags": "boolean"      // Tag immutability
}
```

---

### Infrastructure Assets

#### `host` / `server`
```json
{
  "hostname": "string",            // Hostname
  "fqdn": "string",                // Fully qualified domain name
  "os_family": "string",           // linux, windows, macos
  "os_name": "string",             // Ubuntu, Windows Server, CentOS
  "os_version": "string",          // OS version
  "kernel_version": "string",      // Kernel version
  "architecture": "string",        // x86_64, arm64
  "cpu_count": "integer",          // Number of CPUs
  "memory_gb": "number",           // Memory in GB
  "disk_gb": "number",             // Disk space in GB
  "uptime_days": "number",         // Uptime in days
  "ip_addresses": ["string"],      // All IP addresses
  "mac_addresses": ["string"],     // MAC addresses
  "is_virtual": "boolean",         // Virtual machine
  "hypervisor": "string"           // vmware, kvm, hyperv, xen
}
```

#### `container`
```json
{
  "container_id": "string",        // Container ID
  "name": "string",                // Container name
  "image": "string",               // Image name:tag
  "image_id": "string",            // Image ID
  "runtime": "string",             // docker, containerd, crio
  "state": "string",               // running, stopped, paused
  "created_at": "datetime",        // Creation time
  "started_at": "datetime",        // Start time
  "ports": [                       // Port mappings
    {
      "container_port": "integer",
      "host_port": "integer",
      "protocol": "string"
    }
  ],
  "volumes": ["string"],           // Volume mounts
  "networks": ["string"],          // Networks attached
  "labels": {},                    // Container labels
  "resource_limits": {
    "cpu": "string",
    "memory": "string"
  }
}
```

#### `kubernetes_cluster`
```json
{
  "cluster_name": "string",        // Cluster name
  "provider": "string",            // eks, gke, aks, self-managed
  "version": "string",             // Kubernetes version
  "region": "string",              // Region
  "node_count": "integer",         // Number of nodes
  "namespace_count": "integer",    // Number of namespaces
  "api_server_url": "string",      // API server endpoint
  "network_plugin": "string",      // calico, cilium, flannel
  "ingress_controller": "string",  // nginx, traefik, istio
  "service_mesh": "string",        // istio, linkerd, none
  "rbac_enabled": "boolean",       // RBAC enabled
  "pod_security_enabled": "boolean", // Pod security policies/standards
  "network_policies": "boolean"    // Network policies enabled
}
```

#### `kubernetes_namespace`
```json
{
  "namespace": "string",           // Namespace name
  "cluster_name": "string",        // Parent cluster name
  "labels": {},                    // Namespace labels
  "annotations": {},               // Namespace annotations
  "pod_count": "integer",          // Number of pods
  "service_count": "integer",      // Number of services
  "resource_quota": {              // Resource quotas
    "cpu_limit": "string",
    "memory_limit": "string",
    "pod_limit": "integer"
  },
  "network_policies": ["string"]   // Applied network policies
}
```

#### `database` / `data_store`
```json
{
  "engine": "string",              // postgresql, mysql, mongodb, redis, elasticsearch
  "version": "string",             // Database version
  "provider": "string",            // aws (RDS), gcp (Cloud SQL), azure, self-hosted
  "endpoint": "string",            // Connection endpoint
  "port": "integer",               // Port number
  "instance_class": "string",      // Instance class (db.t3.micro)
  "storage_gb": "integer",         // Storage size
  "storage_type": "string",        // ssd, magnetic
  "multi_az": "boolean",           // Multi-AZ deployment
  "encrypted": "boolean",          // Encryption at rest
  "ssl_enforced": "boolean",       // SSL required
  "publicly_accessible": "boolean",// Public access
  "backup_retention_days": "integer", // Backup retention
  "maintenance_window": "string"   // Maintenance window
}
```

---

### Network Assets

#### `network`
```json
{
  "cidr": "string",                // CIDR block
  "gateway": "string",             // Default gateway
  "dns_servers": ["string"],       // DNS servers
  "dhcp_enabled": "boolean",       // DHCP enabled
  "vlan_id": "integer"             // VLAN ID
}
```

#### `vpc`
```json
{
  "provider": "string",            // aws, gcp, azure
  "vpc_id": "string",              // VPC ID
  "cidr_block": "string",          // Primary CIDR
  "secondary_cidrs": ["string"],   // Secondary CIDRs
  "region": "string",              // Region
  "is_default": "boolean",         // Is default VPC
  "dns_support": "boolean",        // DNS support enabled
  "dns_hostnames": "boolean",      // DNS hostnames enabled
  "subnet_count": "integer",       // Number of subnets
  "internet_gateway": "boolean",   // IGW attached
  "nat_gateway": "boolean",        // NAT gateway present
  "flow_logs_enabled": "boolean",  // Flow logs enabled
  "tags": {}                       // Resource tags
}
```

#### `subnet`
```json
{
  "provider": "string",            // aws, gcp, azure
  "subnet_id": "string",           // Subnet ID
  "vpc_id": "string",              // Parent VPC ID
  "cidr_block": "string",          // CIDR block
  "availability_zone": "string",   // Availability zone
  "is_public": "boolean",          // Public subnet (has route to IGW)
  "map_public_ip": "boolean",      // Auto-assign public IP
  "available_ips": "integer",      // Available IP count
  "route_table_id": "string",      // Associated route table
  "nacl_id": "string",             // Network ACL ID
  "tags": {}                       // Resource tags
}
```

#### `load_balancer`
```json
{
  "provider": "string",            // aws, gcp, azure
  "type": "string",                // application, network, classic, gateway
  "name": "string",                // LB name
  "dns_name": "string",            // DNS name
  "scheme": "string",              // internet-facing, internal
  "vpc_id": "string",              // VPC ID
  "subnets": ["string"],           // Subnet IDs
  "security_groups": ["string"],   // Security group IDs
  "listeners": [                   // Listener configurations
    {
      "port": "integer",
      "protocol": "string",        // HTTP, HTTPS, TCP, UDP
      "target_port": "integer",
      "target_protocol": "string"
    }
  ],
  "health_check": {
    "path": "string",
    "interval_seconds": "integer",
    "timeout_seconds": "integer"
  },
  "ssl_policy": "string",          // SSL policy name
  "access_logs_enabled": "boolean" // Access logging enabled
}
```

#### `firewall`
```json
{
  "provider": "string",            // aws (security group), gcp (firewall rule), azure (nsg)
  "firewall_id": "string",         // Firewall/SG ID
  "name": "string",                // Name
  "vpc_id": "string",              // VPC ID
  "direction": "string",           // inbound, outbound, both
  "rules": [                       // Firewall rules
    {
      "direction": "string",       // inbound, outbound
      "protocol": "string",        // tcp, udp, icmp, all
      "port_range": "string",      // "80", "443", "1024-65535", "all"
      "source": "string",          // CIDR, security group, tag
      "action": "string"           // allow, deny
    }
  ],
  "associated_resources": ["string"], // Attached instances/interfaces
  "tags": {}                       // Resource tags
}
```

---

### Identity & Access Assets

#### `iam_user`
```json
{
  "provider": "string",            // aws, gcp, azure
  "user_id": "string",             // User ID
  "username": "string",            // Username
  "arn": "string",                 // User ARN
  "email": "string",               // Email address
  "created_at": "datetime",        // Creation time
  "last_login": "datetime",        // Last login time
  "password_last_used": "datetime", // Password last used
  "mfa_enabled": "boolean",        // MFA enabled
  "access_keys": [                 // Access keys
    {
      "key_id": "string",
      "status": "string",          // active, inactive
      "created_at": "datetime",
      "last_used": "datetime"
    }
  ],
  "groups": ["string"],            // Group memberships
  "policies": ["string"],          // Attached policies
  "permissions_boundary": "string" // Permissions boundary ARN
}
```

#### `iam_role`
```json
{
  "provider": "string",            // aws, gcp, azure
  "role_id": "string",             // Role ID
  "role_name": "string",           // Role name
  "arn": "string",                 // Role ARN
  "description": "string",         // Role description
  "created_at": "datetime",        // Creation time
  "max_session_duration": "integer", // Max session duration (seconds)
  "trust_policy": {},              // Assume role policy (principals)
  "policies": ["string"],          // Attached policies
  "permissions_boundary": "string", // Permissions boundary ARN
  "instance_profiles": ["string"], // Associated instance profiles
  "last_used": "datetime",         // Last role assumption
  "tags": {}                       // Resource tags
}
```

#### `service_account`
```json
{
  "provider": "string",            // aws, gcp, azure, kubernetes
  "account_id": "string",          // Service account ID
  "email": "string",               // Service account email (GCP)
  "display_name": "string",        // Display name
  "created_at": "datetime",        // Creation time
  "keys": [                        // Service account keys
    {
      "key_id": "string",
      "created_at": "datetime",
      "expires_at": "datetime"
    }
  ],
  "roles": ["string"],             // Assigned roles
  "namespace": "string",           // Kubernetes namespace (if k8s SA)
  "workload_identity": {           // GKE Workload Identity
    "enabled": "boolean",
    "gcp_service_account": "string"
  }
}
```

---

### Reconnaissance Assets

#### `http_service`
```json
{
  "url": "string",                 // Full URL
  "host": "string",                // Hostname
  "port": "integer",               // Port
  "scheme": "string",              // http, https
  "status_code": "integer",        // HTTP status code
  "title": "string",               // Page title
  "content_length": "integer",     // Content length
  "content_type": "string",        // Content-Type header
  "server": "string",              // Server header
  "technologies": ["string"],      // Detected technologies
  "cdn": "string",                 // CDN detected
  "waf": "string",                 // WAF detected
  "tls_version": "string",         // TLS version
  "response_time_ms": "integer",   // Response time
  "redirect_url": "string",        // Final redirect URL
  "screenshot_path": "string"      // Screenshot file path
}
```

#### `open_port`
```json
{
  "host": "string",                // Host IP/hostname
  "port": "integer",               // Port number
  "protocol": "string",            // tcp, udp
  "state": "string",               // open, filtered
  "service": "string",             // Detected service
  "version": "string",             // Service version
  "banner": "string",              // Service banner
  "cpe": "string",                 // CPE identifier
  "discovery_tool": "string"       // nmap, naabu, masscan
}
```

#### `discovered_url`
```json
{
  "url": "string",                 // Full URL
  "method": "string",              // HTTP method
  "status_code": "integer",        // Response status
  "content_type": "string",        // Content type
  "content_length": "integer",     // Content length
  "source": "string",              // Discovery source: crawler, js_analysis, sitemap
  "depth": "integer",              // Crawl depth
  "parameters": ["string"],        // URL parameters found
  "forms": [                       // Forms found
    {
      "action": "string",
      "method": "string",
      "inputs": ["string"]
    }
  ]
}
```

---

## Indexing Recommendations

For frequently queried properties, consider adding GIN indexes:

```sql
-- Index for cloud provider queries
CREATE INDEX idx_assets_properties_provider
ON assets USING GIN ((properties -> 'provider'));

-- Index for IP address queries
CREATE INDEX idx_assets_properties_public_ip
ON assets USING GIN ((properties -> 'public_ip'));

-- Index for service port queries
CREATE INDEX idx_assets_properties_port
ON assets USING GIN ((properties -> 'port'));

-- Composite index for cloud resources
CREATE INDEX idx_assets_properties_cloud
ON assets USING GIN (properties jsonb_path_ops)
WHERE asset_type IN ('compute', 'storage', 'serverless', 'vpc', 'subnet');
```

## Query Examples

```sql
-- Find all AWS compute instances in us-east-1
SELECT * FROM assets
WHERE asset_type = 'compute'
AND properties->>'provider' = 'aws'
AND properties->>'region' = 'us-east-1';

-- Find all public S3 buckets
SELECT * FROM assets
WHERE asset_type = 's3_bucket'
AND properties->>'public_access' = 'public';

-- Find all domains expiring in next 30 days
SELECT * FROM assets
WHERE asset_type = 'domain'
AND (properties->>'expires_at')::timestamp < NOW() + INTERVAL '30 days';

-- Find all services with default credentials
SELECT * FROM assets
WHERE asset_type = 'service'
AND (properties->>'default_credentials')::boolean = true;
```

## Validation

Properties are validated at multiple layers:

### 1. SDK Type Validation
The SDK defines typed Go structs (`AssetTechnical`, `DomainTechnical`, etc.) that
are serialized to JSON and stored in the `properties` JSONB field.

See: `sdk/pkg/ctis/types.go` for the canonical type definitions.

### 2. Properties Validator
The API includes a `PropertiesValidator` that validates properties based on asset type.
This provides runtime validation for:

- **Property limits**: Max 100 properties per asset, max key length 100 chars
- **Key format**: Must be alphanumeric with underscores (e.g., `discovery_source`)
- **Type-specific schemas**: Each asset type has validated fields

See: `api/pkg/validator/properties.go` for the validator implementation.

**Usage example:**

```go
validator := validator.NewPropertiesValidator()
errors := validator.ValidateProperties("domain", properties)
if len(errors) > 0 {
    // Handle validation errors
}
```

### 3. Validated Fields by Asset Type

| Asset Type | Validated Fields |
|------------|------------------|
| `domain` | `registered_at`, `expires_at` (RFC3339), `dns_records` (type, ttl) |
| `subdomain` | `parent_domain` (valid domain), `resolved_ips` (valid IPs), `discovery_source` |
| `ip_address` | `version` (4/6), `asn`, `country` (ISO), `ports` (port/protocol/state), `geolocation` |
| `certificate` | `not_before`, `not_after` (RFC3339), `key_size` (valid sizes) |
| `website` | `url` (valid URL), `response_code` (100-599), `tls_version` |
| `api` | `base_url`, `api_type`, `authentication` |
| `service` | `port` (1-65535), `transport` (tcp/udp), `state` |
| `cloud_*` | `provider` (aws/gcp/azure), `public_access` |
| `kubernetes_cluster` | `provider` (eks/gke/aks), `node_count` |
| `kubernetes_namespace` | `namespace` (valid k8s name), `pod_count` |
| `vpc`, `subnet` | `cidr_block` (valid CIDR) |
| `iam_*` | `provider`, `created_at` |
| `open_port` | `port`, `protocol`, `state` |

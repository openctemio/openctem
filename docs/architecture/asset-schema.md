# CTEM Asset Schema (CTAS)

> **Version**: 1.0
> **Last Updated**: 2024-01-16
> **Status**: Draft

## Overview

CTEM Asset Schema (CTAS) is a standardized JSON format for asset ingestion, inspired by industry standards like SARIF (for static analysis) and CycloneDX (for SBOM).

## Design Goals

1. **Consistency** - All sources use the same format
2. **Validation** - JSON Schema for validation
3. **Extensibility** - Support custom metadata
4. **Interoperability** - Easy to convert from/to other formats

## Schema Structure

```
CTAS Document
├── version          # Schema version
├── metadata         # Source info, timestamp
│   ├── source       # Who sent this data
│   └── timestamp    # When it was sent
└── assets[]         # Array of assets
    ├── identifier   # Name, type, external_id
    ├── classification # Criticality, exposure, scope
    ├── attributes   # Description, owner, tags
    ├── technical    # Type-specific technical details
    ├── relationships # Links to other assets
    └── evidence     # Discovery evidence
```

## Full Schema Definition

### Root Object

```json
{
  "$schema": "https://openctem.io/schemas/ctas/v1.0.json",
  "version": "1.0",
  "metadata": { ... },
  "assets": [ ... ]
}
```

### Metadata

```json
{
  "metadata": {
    "source": {
      "type": "scanner",           // integration|collector|scanner|manual
      "name": "nuclei-scanner-01", // Source name
      "version": "3.1.0",          // Source version (optional)
      "ref": "scan-job-12345"      // External reference (optional)
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "tenant_id": "uuid"            // Optional, can be from auth
  }
}
```

### Asset Object

```json
{
  "identifier": {
    "name": "api.example.com",     // REQUIRED: Unique name
    "type": "domain",              // REQUIRED: Asset type
    "external_id": "route53-Z123"  // ID from source system
  },

  "classification": {
    "criticality": "critical",     // critical|high|medium|low
    "exposure": "public",          // public|restricted|private
    "scope": "in_scope",           // in_scope|out_of_scope|pending
    "environment": "production",   // production|staging|development|testing
    "data_classification": "confidential" // public|internal|confidential|restricted
  },

  "attributes": {
    "description": "Main API endpoint",
    "owner": "platform-team",
    "team": "engineering",
    "tags": ["api", "production"],
    "labels": {
      "cost-center": "123",
      "compliance": "pci-dss"
    }
  },

  "technical": {
    // Type-specific fields (see below)
  },

  "relationships": [
    {
      "type": "belongs_to",
      "target": { "type": "application", "name": "Main Platform" }
    }
  ],

  "evidence": {
    "discovery_method": "dns_enumeration",
    "raw_data": "...",
    "screenshots": ["https://..."]
  }
}
```

## Asset Types & Technical Fields

### Domain Assets

```json
{
  "identifier": { "type": "domain", "name": "example.com" },
  "technical": {
    "domain": {
      "fqdn": "example.com",
      "registrar": "cloudflare",
      "registration_date": "2020-01-01",
      "expiry_date": "2025-01-01",
      "nameservers": ["ns1.cloudflare.com"],
      "whois": { ... }
    },
    "dns": {
      "records": [
        { "type": "A", "value": "1.2.3.4", "ttl": 300 },
        { "type": "MX", "value": "mail.example.com", "priority": 10 }
      ]
    }
  }
}
```

### IP Address Assets

```json
{
  "identifier": { "type": "ip_address", "name": "1.2.3.4" },
  "technical": {
    "network": {
      "ip_version": 4,
      "asn": 12345,
      "as_org": "Example Corp",
      "cidr": "1.2.3.0/24",
      "geolocation": {
        "country": "US",
        "region": "California",
        "city": "San Francisco"
      }
    },
    "ports": [
      { "port": 80, "protocol": "tcp", "service": "http", "banner": "nginx" },
      { "port": 443, "protocol": "tcp", "service": "https", "tls_version": "1.3" }
    ]
  }
}
```

### Repository Assets

```json
{
  "identifier": { "type": "repository", "name": "org/api-service" },
  "technical": {
    "repository": {
      "full_name": "org/api-service",
      "provider": "github",
      "visibility": "private",
      "default_branch": "main",
      "clone_url": "https://github.com/org/api-service.git",
      "web_url": "https://github.com/org/api-service",
      "language": "Go",
      "languages": { "Go": 80, "Shell": 15, "Dockerfile": 5 },
      "topics": ["api", "microservice"],
      "stats": {
        "stars": 10,
        "forks": 2,
        "open_issues": 5,
        "size_kb": 1024
      },
      "timestamps": {
        "created_at": "2023-01-01T00:00:00Z",
        "updated_at": "2024-01-15T10:00:00Z",
        "pushed_at": "2024-01-15T09:00:00Z"
      }
    }
  }
}
```

### Cloud Resource Assets

```json
{
  "identifier": { "type": "compute", "name": "prod-api-instance-1" },
  "technical": {
    "cloud": {
      "provider": "aws",
      "account_id": "123456789012",
      "region": "us-east-1",
      "resource_type": "ec2:instance",
      "resource_id": "i-0123456789abcdef0",
      "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0"
    },
    "compute": {
      "instance_type": "t3.medium",
      "state": "running",
      "private_ip": "10.0.1.100",
      "public_ip": "1.2.3.4",
      "vpc_id": "vpc-12345",
      "subnet_id": "subnet-12345",
      "security_groups": ["sg-web", "sg-default"],
      "iam_role": "prod-api-role"
    }
  }
}
```

### Container/K8s Assets

```json
{
  "identifier": { "type": "kubernetes_cluster", "name": "prod-cluster" },
  "technical": {
    "kubernetes": {
      "cluster_name": "prod-cluster",
      "version": "1.28.0",
      "provider": "eks",
      "endpoint": "https://xxx.eks.amazonaws.com",
      "node_count": 10,
      "namespaces": ["default", "kube-system", "production"]
    }
  }
}
```

### Certificate Assets

```json
{
  "identifier": { "type": "certificate", "name": "api.example.com SSL" },
  "technical": {
    "certificate": {
      "serial_number": "abc123",
      "issuer": "Let's Encrypt",
      "subject": "CN=api.example.com",
      "subject_alt_names": ["api.example.com", "*.api.example.com"],
      "valid_from": "2024-01-01T00:00:00Z",
      "valid_until": "2024-04-01T00:00:00Z",
      "signature_algorithm": "SHA256-RSA",
      "key_algorithm": "RSA",
      "key_size": 2048,
      "fingerprint_sha256": "abc123..."
    }
  }
}
```

## Relationship Types

| Type | Description | Example |
|------|-------------|---------|
| `belongs_to` | Asset is part of another | Server belongs to Application |
| `hosted_on` | Asset runs on infrastructure | App hosted on K8s cluster |
| `depends_on` | Asset requires another | API depends on Database |
| `connected_to` | Network connectivity | Server connected to Load Balancer |
| `parent_of` | Hierarchical parent | Domain parent of Subdomain |
| `child_of` | Hierarchical child | Subdomain child of Domain |

## Validation

### Using JSON Schema

```bash
# Validate with ajv-cli
npm install -g ajv-cli
ajv validate -s ctas-v1.0.schema.json -d assets.json
```

### Validation Errors

```json
{
  "valid": false,
  "errors": [
    {
      "path": "/assets/0/identifier/type",
      "keyword": "enum",
      "message": "must be equal to one of the allowed values",
      "params": { "allowedValues": ["domain", "server", "..."] }
    }
  ]
}
```

## Content Types

### Request

```
POST /api/v1/ingest
Content-Type: application/vnd.openctem.asset+json; version=1.0

{ CTAS document }
```

### Alternative (with query param)

```
POST /api/v1/ingest?schema=ctas&version=1.0
Content-Type: application/json

{ CTAS document }
```

## Example: Complete Document

```json
{
  "$schema": "https://openctem.io/schemas/ctas/v1.0.json",
  "version": "1.0",

  "metadata": {
    "source": {
      "type": "scanner",
      "name": "network-scanner-prod-01",
      "version": "2.1.0",
      "ref": "scan-20240115-001"
    },
    "timestamp": "2024-01-15T10:30:00Z"
  },

  "assets": [
    {
      "identifier": {
        "name": "api.example.com",
        "type": "domain",
        "external_id": "dns-scan-12345"
      },
      "classification": {
        "criticality": "high",
        "exposure": "public",
        "scope": "in_scope",
        "environment": "production"
      },
      "attributes": {
        "description": "Main API endpoint",
        "owner": "platform-team",
        "tags": ["api", "production", "customer-facing"]
      },
      "technical": {
        "domain": {
          "fqdn": "api.example.com"
        },
        "dns": {
          "records": [
            { "type": "A", "value": "1.2.3.4" },
            { "type": "A", "value": "1.2.3.5" }
          ]
        }
      },
      "relationships": [
        {
          "type": "belongs_to",
          "target": { "type": "application", "name": "Main Platform" }
        }
      ],
      "evidence": {
        "discovery_method": "dns_zone_transfer",
        "raw_data": "api.example.com. 300 IN A 1.2.3.4"
      }
    },
    {
      "identifier": {
        "name": "1.2.3.4",
        "type": "ip_address"
      },
      "classification": {
        "criticality": "high",
        "exposure": "public"
      },
      "technical": {
        "network": {
          "ip_version": 4,
          "asn": 12345
        },
        "ports": [
          { "port": 443, "protocol": "tcp", "service": "https" },
          { "port": 80, "protocol": "tcp", "service": "http" }
        ]
      }
    }
  ]
}
```

## Migration from Other Formats

### From Nmap XML

```python
# Pseudo-code
nmap_host = parse_nmap_xml("scan.xml")
ras_asset = {
    "identifier": {
        "name": nmap_host.ip,
        "type": "ip_address"
    },
    "technical": {
        "ports": [
            {"port": p.portid, "protocol": p.protocol, "service": p.service}
            for p in nmap_host.ports
        ]
    }
}
```

### From AWS Config

```python
# Pseudo-code
ec2_instance = aws_config.get_resource("AWS::EC2::Instance", "i-123")
ras_asset = {
    "identifier": {
        "name": ec2_instance.tags.get("Name", ec2_instance.id),
        "type": "compute",
        "external_id": ec2_instance.id
    },
    "technical": {
        "cloud": {
            "provider": "aws",
            "resource_id": ec2_instance.id,
            "arn": ec2_instance.arn
        },
        "compute": {
            "instance_type": ec2_instance.instance_type,
            "private_ip": ec2_instance.private_ip
        }
    }
}
```

## Versioning

| Version | Status | Changes |
|---------|--------|---------|
| 1.0 | Current | Initial release |

Future versions will maintain backward compatibility where possible.

## Related Documentation

- [Data Sources Architecture](./data-sources.md)
- [Asset Types Reference](./asset-types.md)
- [Ingestion API](../api/ingestion.md)

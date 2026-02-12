# Credential Leak Import API

This document describes the API endpoints for importing and managing credential leaks.

## Overview

The Credential Import API allows you to:
- Import credential leaks from various sources (HIBP, SpyCloud, GitGuardian, etc.)
- Handle deduplication automatically based on fingerprint
- Support both JSON and CSV import formats
- Track credential status (active, resolved, false positive)
- Reactivate resolved credentials found again

## Endpoints

### Admin Routes (JWT Authentication)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/api/v1/credentials/stats` | Get credential leak statistics | credentials:read |
| GET | `/api/v1/credentials/enums` | Get available enum values | credentials:read |
| POST | `/api/v1/credentials/import` | Import credentials (JSON) | credentials:write |
| POST | `/api/v1/credentials/import/csv` | Import credentials (CSV) | credentials:write |
| GET | `/api/v1/credentials/import/template` | Download CSV template | credentials:read |

### Agent Routes (API Key Authentication)

| Method | Endpoint | Description | Module Required |
|--------|----------|-------------|-----------------|
| POST | `/api/v1/agent/credentials/ingest` | Ingest credentials from agents | `credentials` |

> **Module Gating:** Agent ingest routes require the tenant to have the corresponding module enabled. If the module is not enabled, the API returns `403 MODULE_NOT_ENABLED`.

---

## Import Credentials (JSON)

### Request

```http
POST /api/v1/credentials/import
Content-Type: application/json
Authorization: Bearer <access_token>
```

### Request Body

```json
{
  "credentials": [
    {
      "identifier": "admin@company.com",
      "credential_type": "password",
      "secret_value": "P@ssw0rd123!",
      "source": {
        "type": "data_breach",
        "name": "HIBP",
        "url": "https://haveibeenpwned.com/...",
        "discovered_at": "2024-08-15T00:00:00Z"
      },
      "severity": "critical",
      "classification": "internal",
      "dedup_key": {
        "breach_name": "CompanyXYZ Breach 2024",
        "breach_date": "2024-07-01"
      },
      "context": {
        "username": "admin@company.com",
        "email": "admin@company.com",
        "domain": "company.com"
      },
      "is_verified": true,
      "is_revoked": false,
      "tags": ["critical", "production"],
      "notes": "Admin account found in breach"
    }
  ],
  "options": {
    "dedup_strategy": "update_last_seen",
    "reactivate_resolved": true,
    "notify_reactivated": true,
    "notify_new_critical": true,
    "auto_classify_severity": true
  },
  "metadata": {
    "source_tool": "hibp",
    "batch_id": "batch-2024-08-15",
    "description": "Monthly HIBP sync"
  }
}
```

### Response

```json
{
  "imported": 45,
  "updated": 12,
  "reactivated": 3,
  "skipped": 5,
  "errors": [
    {
      "index": 10,
      "identifier": "invalid@",
      "error": "invalid email format"
    }
  ],
  "details": [
    {
      "index": 0,
      "identifier": "admin@company.com",
      "action": "imported",
      "id": "550e8400-e29b-41d4-a716-446655440000"
    },
    {
      "index": 1,
      "identifier": "dev@company.com",
      "action": "updated",
      "reason": "last_seen_updated",
      "id": "550e8400-e29b-41d4-a716-446655440001"
    },
    {
      "index": 2,
      "identifier": "old@company.com",
      "action": "reactivated",
      "reason": "found_after_resolution",
      "id": "550e8400-e29b-41d4-a716-446655440002"
    },
    {
      "index": 3,
      "identifier": "fp@company.com",
      "action": "skipped",
      "reason": "marked_as_false_positive",
      "id": "550e8400-e29b-41d4-a716-446655440003"
    }
  ],
  "summary": {
    "total_processed": 65,
    "success_count": 60,
    "error_count": 5,
    "critical_count": 8,
    "reactivated_alert_sent": true
  }
}
```

---

## Import Credentials (CSV)

### Request

```http
POST /api/v1/credentials/import/csv
Content-Type: multipart/form-data
Authorization: Bearer <access_token>
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dedup_strategy` | string | `update_last_seen` | How to handle duplicates |
| `reactivate_resolved` | bool | `true` | Reactivate resolved credentials |
| `notify_reactivated` | bool | `true` | Send alerts for reactivated |
| `notify_new_critical` | bool | `true` | Send alerts for new critical |
| `auto_classify_severity` | bool | `true` | Auto-determine severity |

### CSV Format

Required columns:
- `identifier` - The credential identifier (email, username, API key name)
- `credential_type` - Type of credential
- `source_type` - Source where found

Optional columns:
- `secret_value` - The actual leaked credential value (password, API key, etc.)
- `source_name` - Name of the source tool
- `severity` - Severity level
- `classification` - Internal/external/partner/vendor
- `username`, `email`, `domain` - Context information
- `breach_name`, `breach_date` - For data breach sources
- `repository`, `file_path`, `commit_hash` - For code sources
- `discovered_at` - Discovery date (YYYY-MM-DD or ISO8601)
- `is_verified`, `is_revoked` - Status flags
- `tags` - Comma-separated tags
- `notes` - Additional notes

### Example CSV

```csv
identifier,credential_type,secret_value,source_type,source_name,severity,classification,username,domain,breach_name,breach_date,tags,notes
admin@company.com,password,P@ssw0rd123!,data_breach,HIBP,critical,internal,admin@company.com,company.com,CompanyXYZ Breach,2024-07-01,"critical,production",Admin account
api-key-prod,api_key,AKIAIOSFODNN7EXAMPLE,code_repository,GitGuardian,critical,internal,service-account,github.com/company,,,api-key-leak,Found in public repo
```

---

## Credential Types

| Type | Description | Default Severity |
|------|-------------|-----------------|
| `password` | User password | high |
| `password_hash` | Hashed password | high |
| `api_key` | Generic API key | high |
| `access_token` | OAuth/Bearer token | high |
| `refresh_token` | OAuth refresh token | high |
| `private_key` | RSA/EC private key | critical |
| `ssh_key` | SSH private key | critical |
| `certificate` | X.509 certificate with private key | high |
| `aws_key` | AWS Access Key ID + Secret | critical |
| `gcp_key` | GCP Service Account Key | critical |
| `azure_key` | Azure credentials | critical |
| `database_cred` | Database username/password | critical |
| `jwt_secret` | JWT signing secret | high |
| `encryption_key` | Symmetric encryption key | high |
| `webhook_secret` | Webhook verification secret | medium |
| `smtp_cred` | Email server credentials | medium |
| `other` | Other credential type | medium |

---

## Source Types

### Breach Sources
| Type | Description |
|------|-------------|
| `data_breach` | Public breach database (HIBP, etc.) |
| `dark_web` | Dark web monitoring |
| `paste_site` | Pastebin and similar sites |
| `underground_forum` | Hacker forums |

### Code Sources
| Type | Description |
|------|-------------|
| `code_repository` | Public GitHub/GitLab repos |
| `commit_history` | Git history scanning |
| `config_file` | Exposed config files |
| `log_file` | Log files |
| `ci_cd` | CI/CD logs and artifacts |
| `docker_image` | Docker layer analysis |

### Other Sources
| Type | Description |
|------|-------------|
| `phishing` | Phishing campaigns |
| `malware` | Infostealer logs |
| `public_bucket` | S3/GCS public buckets |
| `api_response` | API error leaks |
| `internal_report` | Manual internal findings |
| `other` | Other sources |

---

## Deduplication Strategy

| Strategy | Description |
|----------|-------------|
| `skip` | Skip duplicates entirely |
| `update_last_seen` | Only update `last_seen_at` (default) |
| `update_all` | Update all fields except fingerprint |
| `create_new` | Always create new (respects unique constraint) |

### Fingerprint Calculation

Fingerprints are calculated differently based on source type:

**For Data Breach credentials:**
```
SHA256(tenant_id + identifier + credential_type + breach_name + breach_date)
```

**For Code Repository credentials:**
```
SHA256(tenant_id + identifier + credential_type + repository + file_path + commit_hash[:8])
```

**For Dark Web / Paste Site credentials:**
```
SHA256(tenant_id + identifier + credential_type + source_url OR paste_id)
```

---

## Deduplication Scenarios

| Existing State | Found Again | `reactivate_resolved` | Action |
|----------------|-------------|----------------------|--------|
| (not exists) | New | - | **INSERT** |
| `active` | Same | - | **UPDATE** `last_seen_at` |
| `resolved` | Same | `true` | **REACTIVATE** |
| `resolved` | Same | `false` | **SKIP** |
| `resolved` | Different breach | - | **INSERT** (new incident) |
| `accepted` | Any | - | **UPDATE** `last_seen_at` |
| `false_positive` | Any | - | **SKIP** (user decision) |

---

## Get Enum Values

### Request

```http
GET /api/v1/credentials/enums
Authorization: Bearer <access_token>
```

### Response

```json
{
  "credential_types": [
    "password", "password_hash", "api_key", "access_token", "refresh_token",
    "private_key", "ssh_key", "certificate", "aws_key", "gcp_key", "azure_key",
    "database_cred", "jwt_secret", "encryption_key", "webhook_secret", "smtp_cred", "other"
  ],
  "source_types": [
    "data_breach", "dark_web", "paste_site", "underground_forum",
    "code_repository", "commit_history", "config_file", "log_file", "ci_cd", "docker_image",
    "phishing", "malware", "public_bucket", "api_response", "internal_report", "other"
  ],
  "classifications": ["internal", "external", "partner", "vendor", "unknown"],
  "dedup_strategies": ["skip", "update_last_seen", "update_all", "create_new"],
  "severities": ["critical", "high", "medium", "low", "info"]
}
```

---

## Get Statistics

### Request

```http
GET /api/v1/credentials/stats
Authorization: Bearer <access_token>
```

### Response

```json
{
  "total": 150,
  "by_state": {
    "active": 100,
    "resolved": 35,
    "accepted": 10,
    "false_positive": 5
  },
  "by_severity": {
    "critical": 25,
    "high": 50,
    "medium": 45,
    "low": 20,
    "info": 10
  }
}
```

---

## Agent Ingest Endpoint

Agents use API key authentication to ingest credentials.

### Request

```http
POST /api/v1/agent/credentials/ingest
Content-Type: application/json
X-API-Key: <agent_api_key>
```

The request body is the same as the JSON import endpoint.

### Example Agent Integration

```python
import requests

API_KEY = "your-agent-api-key"
API_URL = "https://api.openctem.io/api/v1/agent/credentials/ingest"

credentials = {
    "credentials": [
        {
            "identifier": "admin@company.com",
            "credential_type": "password",
            "secret_value": "leaked_password_123",  # The actual leaked password
            "source": {
                "type": "data_breach",
                "name": "InternalScanner",
                "discovered_at": "2024-08-15T10:30:00Z"
            },
            "dedup_key": {
                "breach_name": "CompanyXYZ Breach",
                "breach_date": "2024-07-01"
            }
        }
    ],
    "options": {
        "dedup_strategy": "update_last_seen",
        "reactivate_resolved": True
    },
    "metadata": {
        "source_tool": "internal_scanner",
        "batch_id": "scan-2024-08-15"
    }
}

response = requests.post(
    API_URL,
    json=credentials,
    headers={"X-API-Key": API_KEY}
)

result = response.json()
print(f"Imported: {result['imported']}, Updated: {result['updated']}")
```

---

## Integration Sources

| Source | Format | Notes |
|--------|--------|-------|
| Have I Been Pwned | JSON | Domain search API |
| SpyCloud | JSON | Enterprise API |
| GitGuardian | JSON | Secrets detection |
| TruffleHog | JSON | CLI output |
| Gitleaks | JSON/SARIF | CLI output |
| AWS Macie | JSON | S3 findings |
| Manual | CSV/JSON | File upload |

---

## Error Codes

| Code | Description |
|------|-------------|
| `BAD_REQUEST` | Invalid request body |
| `VALIDATION_FAILED` | Field validation errors |
| `UNAUTHORIZED` | Missing or invalid authentication |
| `FORBIDDEN` | Insufficient permissions |
| `INTERNAL_ERROR` | Server error |

---

## Rate Limits

- Admin endpoints: Standard API rate limits
- Agent ingest: 100 requests/minute per agent
- Max credentials per import: 1000

---

## Best Practices

1. **Use batch imports** - Group credentials into batches of 100-500 for optimal performance
2. **Set appropriate dedup strategy** - Use `update_last_seen` for regular scans
3. **Enable reactivation alerts** - Get notified when resolved credentials reappear
4. **Use batch IDs** - Track related imports with metadata.batch_id
5. **Validate before import** - Use the `/enums` endpoint to validate types
6. **Handle partial failures** - Check the `errors` array in response

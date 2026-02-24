# Notification Outbox Test Script Guide

## Overview

The script `test_notification_outbox.sh` is used to test the Notification Outbox API endpoints for a tenant. This script helps tenants monitor and manage their notification sending queue.

> **Note**: This API is tenant-scoped. A tenant can only view and manage its own notifications.

## Requirements

1. **API server running** at `http://localhost:8080` (or another URL)
2. **Access Token** tenant-scoped with `integrations:notifications:read` permission
3. **curl** and **python3** installed

## How to Get an Access Token

### Method 1: Log in via API

```bash
# Log in
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "your_password"
  }'

# The response will contain a refresh_token
# Use the refresh_token to get an access_token for a specific tenant

curl -X POST http://localhost:8080/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1...",
    "tenant_id": "your-tenant-id"
  }'

# Get the access_token from the response
```

### Method 2: Copy from UI

1. Log in to the OpenCTEM UI
2. Open Developer Tools (F12)
3. Go to the Network tab
4. Make an API request
5. Copy the `Authorization` header value (remove the "Bearer " prefix)

## How to Run the Script

### Basic syntax

```bash
./scripts/test_notification_outbox.sh <access_token>
```

### Examples

```bash
# Run with a token
./scripts/test_notification_outbox.sh eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Run with a different API URL (default is localhost:8080)
API_URL=https://api.openctem.io ./scripts/test_notification_outbox.sh eyJhbGciOiJIUzI1...
```

## Steps the Script Performs

### 1. Get Outbox Statistics

```
GET /api/v1/notification-outbox/stats
```

Example result:
```json
{
  "pending": 10,
  "processing": 2,
  "completed": 100,
  "failed": 5,
  "dead": 1,
  "total": 118
}
```

### 2. List entries

```
GET /api/v1/notification-outbox?page=1&page_size=5
```

### 3. Filter by pending status

```
GET /api/v1/notification-outbox?status=pending&page_size=5
```

### 4. Filter by failed status

```
GET /api/v1/notification-outbox?status=failed&page_size=5
```

### 5. Retry a failed entry (if any)

```
POST /api/v1/notification-outbox/{id}/retry
```

### 6. Get details of an entry

```
GET /api/v1/notification-outbox/{id}
```

## Reading Results

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Invalid request |
| 401 | Not authenticated |
| 403 | No admin permission |
| 404 | Entry not found |
| 500 | Server error |

### Entry Status

| Status | Meaning |
|--------|---------|
| `pending` | Waiting to be processed |
| `processing` | Currently being processed by a worker |
| `completed` | Successfully sent |
| `failed` | Failed, will be retried automatically |
| `dead` | Permanently failed, requires manual intervention |

## Troubleshooting

### 401 Unauthorized Error

```
Token is invalid or has expired
-> Get a new token
```

### 403 Forbidden Error

```
Account does not have notification permissions
-> Requires integrations:notifications:read permission
-> Or use an owner/admin account
```

### Connection refused Error

```
Server is not running or wrong URL
-> Check that the server is running
-> Check the API_URL variable
```

### No data

```
Outbox is empty
-> Create a new finding or exposure to trigger a notification
```

## Manual API Usage

### Get statistics

```bash
curl -X GET "http://localhost:8080/api/v1/notification-outbox/stats" \
  -H "Authorization: Bearer $TOKEN"
```

### Filter by status

```bash
# Tenant is automatically determined from the JWT token
# No need to pass a tenant_id parameter
curl -X GET "http://localhost:8080/api/v1/notification-outbox?status=failed" \
  -H "Authorization: Bearer $TOKEN"
```

### Retry an entry

```bash
curl -X POST "http://localhost:8080/api/v1/notification-outbox/entry-id-here/retry" \
  -H "Authorization: Bearer $TOKEN"
```

### Delete an entry

```bash
curl -X DELETE "http://localhost:8080/api/v1/notification-outbox/entry-id-here" \
  -H "Authorization: Bearer $TOKEN"
```

## Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/notification-outbox` | List entries |
| GET | `/api/v1/notification-outbox/stats` | Statistics |
| GET | `/api/v1/notification-outbox/{id}` | Entry details |
| POST | `/api/v1/notification-outbox/{id}/retry` | Retry failed/dead entry |
| DELETE | `/api/v1/notification-outbox/{id}` | Delete entry |

## Query Parameters for List API

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: pending, processing, completed, failed, dead |
| `page` | int | Page number (default: 1) |
| `page_size` | int | Items per page (default: 20, max: 100) |

> **Note**: `tenant_id` is no longer needed because the API automatically filters by tenant from the JWT token.

## Example Output

```
==========================================
Testing Notification Outbox Admin API
==========================================
API URL: http://localhost:8080

1. Getting outbox statistics...
HTTP Status: 200
Statistics:
{
    "pending": 5,
    "processing": 0,
    "completed": 42,
    "failed": 2,
    "dead": 0,
    "total": 49
}

Summary: 5 pending, 49 total

2. Listing outbox entries (first page)...
HTTP Status: 200
Entries:
{
    "data": [...],
    "total": 49,
    "page": 1,
    "per_page": 5,
    "total_pages": 10
}

...

==========================================
Test completed
==========================================
```

---

**Related documentation:**
- [Notification Outbox Pattern](../../docs/architecture/notification-outbox-pattern.md)
- [API CLAUDE.md](../CLAUDE.md)

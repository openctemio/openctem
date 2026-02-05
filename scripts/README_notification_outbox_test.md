# Hướng dẫn sử dụng Test Script Notification Outbox

## Tổng quan

Script `test_notification_outbox.sh` dùng để kiểm tra các API endpoint Notification Outbox của tenant. Script này giúp tenant giám sát và quản lý hàng đợi gửi thông báo của mình.

> **Note**: API này là tenant-scoped. Tenant chỉ có thể xem và quản lý các notification của chính mình.

## Yêu cầu

1. **Server API đang chạy** tại `http://localhost:8080` (hoặc URL khác)
2. **Access Token** tenant-scoped với quyền `integrations:notifications:read`
3. **curl** và **python3** đã được cài đặt

## Cách lấy Access Token

### Cách 1: Đăng nhập qua API

```bash
# Đăng nhập
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "your_password"
  }'

# Response sẽ chứa refresh_token
# Dùng refresh_token để lấy access_token cho tenant cụ thể

curl -X POST http://localhost:8080/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1...",
    "tenant_id": "your-tenant-id"
  }'

# Lấy access_token từ response
```

### Cách 2: Copy từ UI

1. Đăng nhập vào Rediver UI
2. Mở Developer Tools (F12)
3. Vào tab Network
4. Thực hiện một request API
5. Copy giá trị `Authorization` header (bỏ phần "Bearer ")

## Cách chạy Script

### Cú pháp cơ bản

```bash
./scripts/test_notification_outbox.sh <access_token>
```

### Ví dụ

```bash
# Chạy với token
./scripts/test_notification_outbox.sh eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Chạy với API URL khác (mặc định là localhost:8080)
API_URL=https://api.exploop.io ./scripts/test_notification_outbox.sh eyJhbGciOiJIUzI1...
```

## Các bước Script thực hiện

### 1. Lấy thống kê Outbox

```
GET /api/v1/notification-outbox/stats
```

Kết quả ví dụ:
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

### 2. Liệt kê các entry

```
GET /api/v1/notification-outbox?page=1&page_size=5
```

### 3. Lọc theo trạng thái pending

```
GET /api/v1/notification-outbox?status=pending&page_size=5
```

### 4. Lọc theo trạng thái failed

```
GET /api/v1/notification-outbox?status=failed&page_size=5
```

### 5. Retry entry thất bại (nếu có)

```
POST /api/v1/notification-outbox/{id}/retry
```

### 6. Lấy chi tiết một entry

```
GET /api/v1/notification-outbox/{id}
```

## Đọc kết quả

### HTTP Status Codes

| Code | Ý nghĩa |
|------|---------|
| 200 | Thành công |
| 400 | Request không hợp lệ |
| 401 | Chưa đăng nhập |
| 403 | Không có quyền admin |
| 404 | Không tìm thấy entry |
| 500 | Lỗi server |

### Trạng thái Entry

| Status | Ý nghĩa |
|--------|---------|
| `pending` | Đang chờ xử lý |
| `processing` | Đang được worker xử lý |
| `completed` | Đã gửi thành công |
| `failed` | Thất bại, sẽ retry tự động |
| `dead` | Thất bại vĩnh viễn, cần can thiệp thủ công |

## Troubleshooting

### Lỗi 401 Unauthorized

```
Token không hợp lệ hoặc đã hết hạn
→ Lấy token mới
```

### Lỗi 403 Forbidden

```
Tài khoản không có quyền notifications
→ Cần có quyền integrations:notifications:read
→ Hoặc dùng tài khoản owner/admin
```

### Lỗi connection refused

```
Server chưa chạy hoặc sai URL
→ Kiểm tra server đang chạy
→ Kiểm tra biến API_URL
```

### Không có dữ liệu

```
Outbox trống
→ Tạo finding hoặc exposure mới để trigger notification
```

## Sử dụng API thủ công

### Lấy thống kê

```bash
curl -X GET "http://localhost:8080/api/v1/notification-outbox/stats" \
  -H "Authorization: Bearer $TOKEN"
```

### Lọc theo status

```bash
# Tenant được xác định tự động từ JWT token
# Không cần truyền tenant_id parameter
curl -X GET "http://localhost:8080/api/v1/notification-outbox?status=failed" \
  -H "Authorization: Bearer $TOKEN"
```

### Retry một entry

```bash
curl -X POST "http://localhost:8080/api/v1/notification-outbox/entry-id-here/retry" \
  -H "Authorization: Bearer $TOKEN"
```

### Xóa entry

```bash
curl -X DELETE "http://localhost:8080/api/v1/notification-outbox/entry-id-here" \
  -H "Authorization: Bearer $TOKEN"
```

## Các endpoint có sẵn

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| GET | `/api/v1/notification-outbox` | Liệt kê entries |
| GET | `/api/v1/notification-outbox/stats` | Thống kê |
| GET | `/api/v1/notification-outbox/{id}` | Chi tiết entry |
| POST | `/api/v1/notification-outbox/{id}/retry` | Retry entry failed/dead |
| DELETE | `/api/v1/notification-outbox/{id}` | Xóa entry |

## Query Parameters cho List API

| Parameter | Kiểu | Mô tả |
|-----------|------|-------|
| `status` | string | Lọc theo status: pending, processing, completed, failed, dead |
| `page` | int | Số trang (mặc định: 1) |
| `page_size` | int | Số items/trang (mặc định: 20, max: 100) |

> **Note**: `tenant_id` không còn cần thiết vì API tự động lọc theo tenant từ JWT token.

## Ví dụ Output

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

**Tài liệu liên quan:**
- [Notification Outbox Pattern](../../docs/architecture/notification-outbox-pattern.md)
- [API CLAUDE.md](../CLAUDE.md)

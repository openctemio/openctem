# Swag API Documentation Best Practices

## Quick Start

```bash
# Install swag (one-time)
make swagger-install

# Generate swagger docs from code annotations
make swagger
```

## Annotation Format

### Endpoint Annotations

```go
// @Summary      Mô tả ngắn (max 120 chars)
// @Description  Mô tả chi tiết endpoint
// @Tags         TagName
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string           true   "Path parameter"
// @Param        name     query     string           false  "Query parameter"
// @Param        request  body      RequestType      true   "Request body"
// @Success      200  {object}  ResponseType
// @Success      201  {object}  ResponseType  "Created"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /path/{id} [get|post|put|delete]
func (h *Handler) Method(w http.ResponseWriter, r *http.Request) {}
```

### Request/Response Types

Swag sử dụng struct tags để generate schema:

```go
type CreateRequest struct {
    Name        string   `json:"name" validate:"required,min=1,max=255"`
    Description string   `json:"description" validate:"max=1000"`
    Tags        []string `json:"tags" validate:"max=20,dive,max=50"`
}

type Response struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
}
```

## Project Structure

```
api/openapi/
├── openapi.yaml          # OLD: Manual docs (có thể xóa)
└── swagger/
    └── swagger.yaml      # NEW: Auto-generated từ code
```

## Workflow

1. **Thêm/sửa annotations** trong handlers (`internal/infra/http/handler/*.go`)
2. **Generate docs**: `make swagger`
3. **Verify**: Xem `api/openapi/swagger/swagger.yaml`

## Tips

- **Tags**: Nhóm endpoints theo domain (Assets, Projects, Branches...)
- **Security**: Thêm `@Security BearerAuth` cho protected endpoints
- **Errors**: Document tất cả status codes có thể trả về
- **Types**: Dùng struct types thay vì `map[string]interface{}` khi có thể
- **Comments**: Đặt annotations **ngay trước** function declaration

## Handlers với Swag Annotations

| Handler | Endpoints | Status |
|---------|-----------|--------|
| asset_handler.go | 5 | ✅ |
| project_handler.go | 5 | ✅ |
| branch_handler.go | 7 | ✅ |
| health_handler.go | 2 | ✅ |
| dashboard_handler.go | 2 | ✅ |
| sla_handler.go | 7 | ✅ |
| component_handler.go | 6 | ✅ |
| user_handler.go | 4 | ✅ |
| audit_handler.go | 5 | ✅ |
| vulnerability_handler.go | 12 | ✅ |
| local_auth_handler.go | 13 | ✅ |
| tenant_handler.go | 20+ | ⏳ |
| **Total** | **68+** | |



## References

- [Swag Documentation](https://github.com/swaggo/swag)
- [Declarative Comments Format](https://github.com/swaggo/swag#declarative-comments-format)

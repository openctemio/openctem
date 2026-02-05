# API Documentation

This folder contains API specifications.

## Files

- `openapi.yaml` - OpenAPI 3.0 specification (TODO)

## Generate Swagger

```bash
# Install swag
go install github.com/swaggo/swag/cmd/swag@latest

# Generate docs
swag init -g cmd/server/main.go -o docs/api
```

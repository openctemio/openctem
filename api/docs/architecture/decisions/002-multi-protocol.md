# ADR-002: Multi-Protocol API Design

## Status
Accepted

## Context
Need to support multiple client types with different requirements.

## Decision
Implement **three protocols**:

| Protocol | Port | Use Case |
|----------|------|----------|
| HTTP/REST | 8080 | Web clients, simple integrations |
| gRPC | 9090 | High-performance, typed clients |
| WebSocket | 8081 | Real-time updates |

## Rationale

### HTTP/REST
- Universal compatibility
- Easy debugging (curl, Postman)
- OpenAPI documentation

### gRPC
- Strong typing with Protobuf
- Streaming support
- Better performance for internal services

### WebSocket
- Real-time risk updates
- Dashboard live refresh
- Connector status notifications

## Consequences
- More code to maintain
- Need shared service layer (app/)
- Consistent domain model across protocols

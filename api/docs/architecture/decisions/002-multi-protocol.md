# ADR-002: Multi-Protocol API Design

## Status
Accepted; partly implemented.

## Context
Different clients need different transports: the web console and integrations
need a simple request/response API, the console needs live updates, and
sensors need a typed, versioned protocol.

## Decision

| Protocol | Where | Use case | Status |
|----------|-------|----------|--------|
| HTTP/REST | `:8080`, `/api/v1/*` | Web console, integrations, automation | Shipped |
| WebSocket | `:8080`, `/api/v1/ws` (same listener) | Real-time updates in the console ([RFC-045](../../rfcs/RFC-045-websocket-auth.md)) | Shipped |
| Sensor protocol v2 | `:8080`, `/api/v2/sensor/*` | Sensors ([sensors.md](../sensors.md)) | Shipped |
| gRPC | `GRPC_PORT` (default `9090`) | Typed, streaming clients | **Planned**: the port is configured, no gRPC service is served |

## Rationale

- **HTTP/REST:** universal compatibility, easy debugging, OpenAPI documentation.
- **WebSocket:** live dashboard and finding activity without polling.
- **Sensor protocol:** its own plane and authenticator, versioned separately
  from the console API.

## Consequences
- One shared service layer (`internal/app`) behind every transport.
- One domain model across protocols.

# Clean Architecture

## Layer Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  cmd/                     Entry points (main.go)                            │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  internal/infra/       INFRASTRUCTURE LAYER                          │   │
│  │                                                                      │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │   http/  │ │  grpc/   │ │   ws/    │ │ postgres/│ │connector/│  │   │
│  │  │ REST API │ │ gRPC API │ │WebSocket │ │    DB    │ │ Wiz/etc  │  │   │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │   │
│  └───────┼────────────┼────────────┼────────────┼────────────┼─────────┘   │
│          │            │            │            │            │             │
│          └────────────┴────────────┼────────────┴────────────┘             │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  internal/app/         APPLICATION LAYER                             │   │
│  │                                                                      │   │
│  │  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐    │   │
│  │  │  asset_service   │ │ exposure_service │ │  risk_calculator │    │   │
│  │  └────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘    │   │
│  └───────────┼────────────────────┼────────────────────┼───────────────┘   │
│              │                    │                    │                    │
│              └────────────────────┼────────────────────┘                    │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  internal/domain/      DOMAIN LAYER (Pure Business Logic)            │   │
│  │                                                                      │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐               │   │
│  │  │  asset/  │ │ exposure/│ │attackpath│ │  shared/ │               │   │
│  │  │ Entity   │ │ Entity   │ │ Entity   │ │  Types   │               │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘               │   │
│  │                                                                      │   │
│  │  ❌ NO external dependencies                                         │   │
│  │  ❌ NO database, HTTP, framework imports                             │   │
│  │  ✅ Pure Go + standard library only                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Dependency Rules

| Layer | Can Import | Cannot Import |
|-------|------------|---------------|
| `domain/` | Nothing (only stdlib) | app, infra, pkg |
| `app/` | domain | infra |
| `infra/` | domain, app, pkg | - |
| `cmd/` | All layers | - |

---

## Domain Layer (`internal/domain/`)

**Zero external dependencies** - Only standard library.

### asset/
```
├── entity.go          # Asset struct + business methods
├── entity_test.go
├── repository.go      # Repository INTERFACE
├── types.go           # AssetType, Criticality enums
├── types_test.go
├── errors.go          # Domain errors
├── errors_test.go
├── events.go          # Domain events
└── service.go         # Domain service (multi-aggregate logic)
```

### exposure/
```
├── entity.go
├── entity_test.go
├── repository.go
├── types.go           # Category, Severity, Status enums
├── types_test.go
├── errors.go
├── risk_score.go      # RiskScore value object
├── risk_score_test.go
├── exploitability.go  # Exploitability value object
└── reachability.go    # Reachability value object
```

### attackpath/
```
├── entity.go
├── entity_test.go
├── repository.go
├── types.go           # Action, Effort enums
├── errors.go
└── node.go            # PathNode, ChokePoint value objects
```

### validation/
```
├── entity.go          # BAS/Pentest validation
├── repository.go
└── types.go
```

### remediation/
```
├── entity.go          # Remediation tracking
├── repository.go
└── types.go
```

### shared/
```
├── identifier.go      # UUID wrapper
├── pagination.go
├── timestamp.go
└── errors.go
```

---

## App Layer (`internal/app/`)

**Imports only domain** - Orchestrates business logic.

```
├── asset_service.go
├── asset_service_test.go
├── exposure_service.go
├── exposure_service_test.go
├── attackpath_service.go
├── attackpath_service_test.go
├── risk_calculator.go         # Risk calculation orchestration
├── risk_calculator_test.go
├── dashboard_service.go       # Dashboard aggregation
├── dashboard_service_test.go
├── ingestion_service.go       # Data ingestion from connectors
├── ingestion_service_test.go
│
└── dto/                       # Data Transfer Objects
    ├── asset_dto.go
    ├── exposure_dto.go
    └── dashboard_dto.go
```

---

## Infra Layer (`internal/infra/`)

**External dependencies allowed** - Implements interfaces.

### http/ (REST API)

```
Hexagonal / Ports & Adapters
├── Port:    Router interface (router.go)
├── Adapter: Chi implementation (chi_router.go)
├── DTO:     Request/Response structs in handler
└── Handler: Standard net/http signature
```

```
├── server.go          # HTTP server setup
├── router.go          # Router interface (abstraction)
├── chi_router.go      # Chi router implementation
├── routes.go          # Centralized route registration
├── request.go         # Request helpers (PathParam, QueryParam)
│
├── handler/
│   ├── asset.go
│   ├── asset_test.go
│   ├── exposure.go
│   ├── exposure_test.go
│   ├── attackpath.go
│   ├── dashboard.go
│   ├── crown_jewel.go
│   ├── health.go
│   └── health_test.go
│
├── middleware/
│   ├── auth.go
│   ├── auth_test.go
│   ├── cors.go
│   ├── logger.go
│   ├── ratelimit.go
│   ├── requestid.go
│   └── recovery.go
│
└── dto/
    ├── request.go
    ├── response.go
    └── mapper.go      # Domain ↔ HTTP DTO
```

### grpc/
```
├── server.go          # gRPC server setup
│
├── handler/
│   ├── asset.go       # Implements AssetServiceServer
│   ├── asset_test.go
│   ├── exposure.go
│   └── health.go
│
├── interceptor/
│   ├── auth.go
│   ├── logger.go
│   ├── recovery.go
│   └── validator.go
│
├── mapper/
│   ├── asset.go
│   └── exposure.go
│
└── pb/                # Generated Protobuf (auto-generated)
    ├── common.pb.go
    ├── asset.pb.go
    ├── exposure.pb.go
    └──.exploop_grpc.pb.go
```

### ws/ (WebSocket)
```
├── server.go          # WebSocket server setup
├── hub.go             # Connection manager (pub/sub)
├── hub_test.go
├── client.go          # Client connection handler
├── client_test.go
│
├── handler/
│   ├── subscribe.go   # Subscription management
│   ├── broadcast.go   # Broadcast events
│   └── events.go      # Event handlers
│
└── message/
    ├── types.go       # Message type definitions
    ├── incoming.go    # Parse incoming
    └── outgoing.go    # Format outgoing
```

### postgres/
```
├── connection.go              # DB connection pool
├── asset_repository.go        # Implements asset.Repository
├── asset_repository_test.go   # Integration tests
├── exposure_repository.go
├── exposure_repository_test.go
├── attackpath_repository.go
└── migrations.go              # Migration runner
```

### redis/
```
├── client.go          # Redis client
├── cache.go           # Cache implementation
└── pubsub.go          # Pub/Sub for real-time
```

### connector/
```
├── interface.go       # Connector interface
│
├── wiz/
│   ├── client.go      # Wiz API client
│   ├── client_test.go
│   ├── mapper.go      # Map Wiz → Domain
│   └── config.go
│
├── tenable/
│   ├── client.go
│   ├── mapper.go
│   └── config.go
│
├── snyk/
│   ├── client.go
│   ├── mapper.go
│   └── config.go
│
└── crowdstrike/
    ├── client.go
    ├── mapper.go
    └── config.go
```

### queue/ (optional)
```
├── producer.go
└── consumer.go
```

---

## Config (`internal/config/`)
```
├── config.go          # Config struct + loader
└── config_test.go
```

## Mocks (`internal/mocks/`)
```
├── asset_repository.go
├── exposure_repository.go
├── attackpath_repository.go
└── event_publisher.go
```

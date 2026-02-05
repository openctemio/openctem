# Plan: Loại bỏ tính năng Enterprise cho OpenCTEM OSS Edition

## Mục tiêu

Tạo OSS edition sạch:
- Giữ lại module system (để UI biết có features nào)
- Xóa licensing/subscription/billing
- Tất cả modules enabled mặc định, không gating
- Không có dấu vết về enterprise edition

---

## Phân loại: GIỮ vs XÓA

### GIỮ LẠI

| File/Component | Lý do |
|----------------|-------|
| `/pkg/domain/licensing/module.go` | Định nghĩa modules cho UI sidebar |
| `/pkg/domain/licensing/event_type.go` | Event types cho notifications |
| `/internal/app/module_cache_service.go` | Cache modules (sẽ simplify) |
| Bootstrap handler | Return modules cho UI |
| RBAC/Permissions | Core security |
| Audit Logging | Compliance |
| Tenant Isolation | Multi-tenant |
| Groups/Roles | Access control |

### XÓA HOÀN TOÀN

| File/Component | Lý do |
|----------------|-------|
| `/pkg/domain/licensing/plan.go` | Plans/Pricing - enterprise |
| `/pkg/domain/licensing/subscription.go` | Subscriptions - enterprise |
| `/pkg/domain/licensing/repository.go` | Plan/Subscription queries (giữ module queries) |
| `/pkg/domain/sla/` (cả folder) | SLA - enterprise feature |
| `/internal/app/licensing_service.go` | Plan checking, subscription logic |
| `/internal/app/sla_service.go` | SLA business logic |
| `/internal/infra/http/handler/licensing_handler.go` | Billing/subscription endpoints |
| `/internal/infra/http/handler/sla_handler.go` | SLA endpoints |
| `/internal/infra/http/middleware/module.go` | Module gating middleware |
| `/internal/infra/postgres/licensing_repository.go` | Plan/subscription DB (giữ phần module) |
| `/internal/infra/postgres/sla_repository.go` | SLA DB queries |

---

## Chi tiết Implementation

### Phase 1: Restructure Module Domain

**Mục tiêu:** Tách module khỏi licensing, giữ lại như standalone feature list

#### 1.1 Tạo `/pkg/domain/module/` (mới)
Di chuyển và simplify từ licensing:

```go
// /pkg/domain/module/module.go
package module

// Module represents a feature module in the system
type Module struct {
    ID            string
    Slug          string
    Name          string
    Description   string
    Icon          string
    Category      string
    DisplayOrder  int
    IsActive      bool
    ReleaseStatus string // released, coming_soon, beta
    ParentID      string // for sub-modules
    EventTypes    []string
}

// Well-known module IDs (OSS - all available)
const (
    ModuleDashboard    = "dashboard"
    ModuleAssets       = "assets"
    ModuleScans        = "scans"
    ModuleFindings     = "findings"
    ModuleCredentials  = "credentials"
    ModuleComponents   = "components"
    ModuleThreatIntel  = "threat_intel"
    ModulePentest      = "pentest"
    ModuleRemediation  = "remediation"
    ModuleReports      = "reports"
    ModuleIntegrations = "integrations"
    ModuleAudit        = "audit"
    ModuleTeam         = "team"
    ModuleGroups       = "groups"
    ModuleRoles        = "roles"
    ModuleAgents       = "agents"
    ModuleAITriage     = "ai_triage"
)

// GetAllModules returns all available modules (OSS - no restrictions)
func GetAllModules() []Module {
    return []Module{
        {ID: ModuleDashboard, Slug: "dashboard", Name: "Dashboard", Category: "core", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleAssets, Slug: "assets", Name: "Assets", Category: "core", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleScans, Slug: "scans", Name: "Scans", Category: "core", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleFindings, Slug: "findings", Name: "Findings", Category: "core", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleCredentials, Slug: "credentials", Name: "Credentials", Category: "discovery", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleComponents, Slug: "components", Name: "Components", Category: "discovery", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleThreatIntel, Slug: "threat_intel", Name: "Threat Intel", Category: "prioritization", IsActive: true, ReleaseStatus: "released"},
        {ID: ModulePentest, Slug: "pentest", Name: "Penetration Testing", Category: "validation", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleRemediation, Slug: "remediation", Name: "Remediation", Category: "mobilization", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleReports, Slug: "reports", Name: "Reports", Category: "insights", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleIntegrations, Slug: "integrations", Name: "Integrations", Category: "settings", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleAudit, Slug: "audit", Name: "Audit", Category: "compliance", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleTeam, Slug: "team", Name: "Team", Category: "settings", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleGroups, Slug: "groups", Name: "Groups", Category: "settings", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleRoles, Slug: "roles", Name: "Roles", Category: "settings", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleAgents, Slug: "agents", Name: "Agents", Category: "scanning", IsActive: true, ReleaseStatus: "released"},
        {ID: ModuleAITriage, Slug: "ai_triage", Name: "AI Triage", Category: "premium", IsActive: true, ReleaseStatus: "released"},
    }
}

// GetAllModuleIDs returns all module IDs
func GetAllModuleIDs() []string {
    modules := GetAllModules()
    ids := make([]string, len(modules))
    for i, m := range modules {
        ids[i] = m.ID
    }
    return ids
}
```

#### 1.2 Tạo `/pkg/domain/module/event_type.go`
Di chuyển event types:

```go
// /pkg/domain/module/event_type.go
package module

// EventType for notifications
type EventType struct {
    ID       string
    Slug     string
    Name     string
    Category string
}

// GetAllEventTypes returns all event types (OSS - no restrictions)
func GetAllEventTypes() []string {
    return []string{
        "findings",
        "exposures",
        "scans",
        "alerts",
        "assets",
        "credentials",
    }
}
```

---

### Phase 2: Xóa Licensing Domain

```bash
# Xóa files
rm /pkg/domain/licensing/plan.go
rm /pkg/domain/licensing/subscription.go
rm /pkg/domain/licensing/repository.go
rm /pkg/domain/licensing/errors.go

# Giữ lại và migrate sau:
# - module.go -> move to /pkg/domain/module/
# - event_type.go -> move to /pkg/domain/module/

# Sau khi migrate, xóa folder
rm -rf /pkg/domain/licensing/
```

---

### Phase 3: Xóa SLA Domain

```bash
rm -rf /pkg/domain/sla/
```

---

### Phase 4: Simplify Module Cache Service

**File:** `/internal/app/module_cache_service.go`

Simplify để chỉ return static modules:

```go
package app

import (
    "context"
    "github.com/openctemio/api/pkg/domain/module"
)

type ModuleCacheService struct{}

func NewModuleCacheService() *ModuleCacheService {
    return &ModuleCacheService{}
}

// GetAllModules returns all modules (OSS - no caching needed, static list)
func (s *ModuleCacheService) GetAllModules(ctx context.Context) []module.Module {
    return module.GetAllModules()
}

// GetModuleIDs returns all module IDs
func (s *ModuleCacheService) GetModuleIDs(ctx context.Context) []string {
    return module.GetAllModuleIDs()
}

// HasModule always returns true in OSS (no restrictions)
func (s *ModuleCacheService) HasModule(ctx context.Context, tenantID, moduleID string) bool {
    return true
}

// GetEventTypes returns all event types
func (s *ModuleCacheService) GetEventTypes(ctx context.Context) []string {
    return module.GetAllEventTypes()
}
```

---

### Phase 5: Xóa Services

```bash
rm /internal/app/licensing_service.go
rm /internal/app/sla_service.go
```

---

### Phase 6: Xóa Handlers

```bash
rm /internal/infra/http/handler/licensing_handler.go
rm /internal/infra/http/handler/sla_handler.go
```

---

### Phase 7: Xóa Middleware

```bash
rm /internal/infra/http/middleware/module.go
```

---

### Phase 8: Xóa Repositories

```bash
rm /internal/infra/postgres/licensing_repository.go
rm /internal/infra/postgres/sla_repository.go
```

---

### Phase 9: Sửa Routes

**File:** `/internal/infra/http/routes/routes.go`
- Xóa `registerLicensingRoutes()`
- Xóa `registerSLARoutes()`
- Xóa parameter `licensingService` từ các functions

**File:** `/internal/infra/http/routes/misc.go`
- Xóa `registerLicensingRoutes()` function
- Xóa `registerSLARoutes()` function
- Xóa `middleware.RequireModule` calls
- Xóa `middleware.RequireSubModule` calls
- Xóa import licensing package

**File:** `/internal/infra/http/routes/scanning.go`
- Xóa parameter `licensingService`
- Xóa `middleware.RequireModule()` calls
- Xóa `middleware.RequireModuleForAgent()` calls

**File:** `/internal/infra/http/routes/assets.go`
- Xóa parameter `licensingService`
- Xóa module check middleware

---

### Phase 10: Sửa DI (Dependency Injection)

**File:** `/cmd/server/repositories.go`
- Xóa `Licensing` repository

**File:** `/cmd/server/services.go`
- Xóa `Licensing` service
- Xóa `SLA` service
- Simplify `ModuleCache` service (không cần Redis)

**File:** `/cmd/server/handlers.go`
- Xóa `Licensing` handler
- Xóa `SLA` handler

---

### Phase 11: Sửa Bootstrap Handler

**File:** `/internal/infra/http/handler/bootstrap_handler.go`

```go
package handler

import (
    "encoding/json"
    "net/http"
    "sort"

    "github.com/openctemio/api/internal/app"
    "github.com/openctemio/api/pkg/domain/module"
)

type BootstrapHandler struct {
    permCacheSvc   *app.PermissionCacheService
    permVersionSvc *app.PermissionVersionService
    moduleSvc      *app.ModuleCacheService
}

type BootstrapResponse struct {
    Permissions BootstrapPermissions `json:"permissions"`
    Modules     *BootstrapModules    `json:"modules"`
}

type BootstrapPermissions struct {
    List    []string `json:"list"`
    Version int      `json:"version"`
}

type BootstrapModules struct {
    ModuleIDs  []string        `json:"module_ids"`
    Modules    []module.Module `json:"modules"`
    EventTypes []string        `json:"event_types"`
}

func (h *BootstrapHandler) GetBootstrap(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Get permissions (existing logic)
    permissions, _ := h.permCacheSvc.GetPermissionsWithFallback(ctx, tenantID, userID)
    sort.Strings(permissions)
    version := h.permVersionSvc.Get(ctx, tenantID, userID)

    // Get modules (OSS - all modules)
    modules := module.GetAllModules()
    moduleIDs := module.GetAllModuleIDs()
    eventTypes := module.GetAllEventTypes()

    response := BootstrapResponse{
        Permissions: BootstrapPermissions{
            List:    permissions,
            Version: version,
        },
        Modules: &BootstrapModules{
            ModuleIDs:  moduleIDs,
            Modules:    modules,
            EventTypes: eventTypes,
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// GetModules returns all available modules
func (h *BootstrapHandler) GetModules(w http.ResponseWriter, r *http.Request) {
    response := &BootstrapModules{
        ModuleIDs:  module.GetAllModuleIDs(),
        Modules:    module.GetAllModules(),
        EventTypes: module.GetAllEventTypes(),
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

---

### Phase 12: Sửa Other Services (nếu có references)

**File:** `/internal/app/tenant_service.go`
- Xóa code tạo default SLA policy
- Xóa references đến licensing

**File:** `/internal/app/ai_triage_service.go`
- Xóa licensing token limit checks
- Set unlimited hoặc xóa check

**File:** `/internal/app/agent_selector.go`
- Xóa platform agent tier checks
- Simplify selection logic

---

### Phase 13: Build & Test

```bash
cd /home/ubuntu/projects/openctemio/api

# Build
go build ./...

# Run tests
go test ./...

# Verify no licensing references
grep -r "licensing" --include="*.go" | grep -v "_test.go" | grep -v "PLAN_"
grep -r "subscription" --include="*.go" | grep -v "_test.go"
grep -r "RequireModule" --include="*.go"
```

---

## API Response (OSS Edition)

### GET /api/v1/me/bootstrap
```json
{
  "permissions": {
    "list": ["assets:read", "findings:write", ...],
    "version": 1
  },
  "modules": {
    "module_ids": ["dashboard", "assets", "scans", "findings", ...],
    "modules": [
      {"id": "dashboard", "slug": "dashboard", "name": "Dashboard", "category": "core", "is_active": true, "release_status": "released"},
      {"id": "assets", "slug": "assets", "name": "Assets", "category": "core", "is_active": true, "release_status": "released"},
      ...
    ],
    "event_types": ["findings", "exposures", "scans", "alerts", "assets", "credentials"]
  }
}
```

### GET /api/v1/me/modules
```json
{
  "module_ids": ["dashboard", "assets", "scans", ...],
  "modules": [...],
  "event_types": [...]
}
```

---

## Summary

| Action | Items |
|--------|-------|
| **Tạo mới** | `/pkg/domain/module/` (tách từ licensing) |
| **Xóa** | ~10 files + 2 folders |
| **Sửa** | ~12 files |

**Kết quả:**
- Module system vẫn hoạt động (UI sidebar)
- Không có licensing/subscription/billing
- Tất cả modules enabled mặc định
- Clean codebase, không có enterprise traces

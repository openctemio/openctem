# #340 — Azure Connector (Resource Graph)

- **Q/WS**: Q2 / WS-A
- **Status**: Pending — blocked on Azure service-principal for sandbox subscription
- **Seam**: `internal/app/connector/connector.go`
- **Related**: #339 GCP (same pattern), #327 AWS v1

## 1. Scope

**Ships:**
- `internal/app/connector/azure/` implementing `connector.Connector`.
- Resource enumeration via **Azure Resource Graph** (single KQL query covers every resource type).
- Subscription-scoped discovery in v1 (management-group scope is a follow-up).
- Integration test against a sandbox subscription (skipped in CI unless `AZURE_TEST_*` env set).
- Feature flag `connectors.azure.enabled`.

**Does NOT ship:**
- Management-group scope (cross-subscription enumeration).
- Azure AD user/group enumeration.
- Delta sync — v1 is full enumeration per run.
- Diagnostic settings / monitor integration.

## 2. External dependencies

| What | Why | Source |
|---|---|---|
| `github.com/Azure/azure-sdk-for-go/sdk/resourcegraph/armresourcegraph` | KQL client | `go get github.com/Azure/azure-sdk-for-go/sdk/resourcegraph/armresourcegraph` |
| `github.com/Azure/azure-sdk-for-go/sdk/azidentity` | SP auth | transitive |
| Sandbox subscription | Integration test target | user provides |
| Service principal with `Reader` on subscription | Read permission | `az ad sp create-for-rbac --role Reader --scopes /subscriptions/$SUB_ID` |

**Rationale:** Resource Graph is Azure's equivalent of GCP CAI — one KQL query enumerates everything. Avoid per-service ARM clients (armcompute, armstorage, ...) — they multiply code size and each has its own pagination/retry quirks.

## 3. Data model

### 3.1 Credentials (already in `connector.Credentials`)

```go
type Credentials struct {
    TenantID       string // Azure AD tenant (≠ OpenCTEM tenant — naming clash, see Open Q1)
    ClientID       string // SP app id
    ClientSecret   string // SP secret, decrypted by caller
    SubscriptionID string // target subscription
}
```

Validation:
- `TenantID` is a UUID.
- `ClientID` is a UUID.
- `ClientSecret` non-empty, length 10-256.
- `SubscriptionID` is a UUID.

### 3.2 Per-asset properties

```json
{
  "cloud_provider": "azure",
  "azure_subscription_id": "...",
  "azure_resource_group": "rg-prod",
  "azure_resource_id": "/subscriptions/.../resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1",
  "azure_resource_type": "Microsoft.Compute/virtualMachines",
  "azure_location": "eastus",
  "azure_tags": { "env": "prod" },
  "azure_sku": "Standard_D2s_v3"
}
```

## 4. Public interface

```go
// internal/app/connector/azure/azure.go
package azure

type Connector struct {
    clientFactory func(ctx context.Context, creds connector.Credentials) (rg, error)
}

type rg interface {
    Query(ctx context.Context, req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error)
}

func New() *Connector

func (c *Connector) Provider() connector.Provider // "azure"
func (c *Connector) Validate(ctx context.Context, creds connector.Credentials) error
func (c *Connector) Discover(ctx context.Context, tenantID shared.ID, creds connector.Credentials) (*connector.DiscoveryResult, error)
```

### 4.1 KQL query (pin this)

```kql
Resources
| project id, name, type, location, resourceGroup, subscriptionId, tags, sku, kind, properties
| limit 1000
```

Pagination via `$skipToken` — loop until empty. Page size 1000 is the Azure max.

**Do NOT** `project properties` without a column cap — some resource types (e.g. `Microsoft.Network/networkSecurityGroups`) have 50+ KB properties blobs, and the 32 MB response cap will trip. Strip `properties` to just the fields the mapping table uses (see §5).

## 5. Resource mapping

| Azure resource_type | Internal `AssetType` | Notes |
|---|---|---|
| `microsoft.compute/virtualmachines` | `TypeVirtualMachine` | `properties.osProfile.computerName` → `hostname` |
| `microsoft.compute/disks` | `TypeStorage` | skip if attached to VM (dedup) |
| `microsoft.storage/storageaccounts` | `TypeStorageBucket` | check `properties.allowBlobPublicAccess` |
| `microsoft.sql/servers/databases` | `TypeDatabase` | parent server id → `properties.db_server_id` |
| `microsoft.documentdb/databaseaccounts` | `TypeDatabase` | CosmosDB |
| `microsoft.containerservice/managedclusters` | `TypeKubernetesCluster` | AKS — `properties.fqdn` → `api_endpoint` |
| `microsoft.web/sites` | `TypeWebApp` | App Service |
| `microsoft.web/sites/functions` | `TypeServerlessFunction` | Functions |
| `microsoft.network/virtualnetworks` | `TypeNetwork` | `properties.addressSpace.addressPrefixes` → `cidrs` |
| `microsoft.network/publicipaddresses` | `TypeNetwork` | `properties.ipAddress` → `ip_address` |
| `microsoft.keyvault/vaults` | `TypeSecretsStore` | `properties.vaultUri` → `endpoint` |
| `microsoft.insights/components` | `TypeMonitoring` | App Insights — skip unless product wants it |

**Pre-coding check:** `az graph query -q "Resources | summarize count() by type" --subscription $SUB` to see the actual distribution in the sandbox, and update the table.

## 6. Test plan

### 6.1 Unit
- `TestValidate_BadUUID_Rejected` — each UUID field individually.
- `TestValidate_EmptySecret_Rejected`.
- `TestDiscover_MapsKnownTypes` — fake RG returns one of each mapped type.
- `TestDiscover_UnknownType_FallsBack` — fake returns `microsoft.foo/bar` → `TypeUnknown`.
- `TestDiscover_Pagination` — fake returns 3 pages via `$skipToken`, assert all 3 pages' resources merged.
- `TestDiscover_PageError_Continues` — mid-pagination error → partial result + error recorded.
- `TestDiscover_RateLimit_BackoffRespected` — fake returns 429 with `Retry-After`, assert correct wait.

### 6.2 Integration
Build tag `integration_azure`. Uses `AZURE_TEST_*` env. Creates 2-3 resources via `az cli` in a `test-ctem-{timestamp}` resource group, runs Discover, asserts, tears down RG.

## 7. Rollout

Identical to #339 — flag off → unit → integration → staging tenant → all tenants.

## 8. Open questions

| # | Question | Who answers | Default |
|---|---|---|---|
| Q1 | Naming: `Credentials.TenantID` collides with OpenCTEM tenant. Rename to `AzureTenantID`? | Platform | Yes — land as breaking change, AWS/GCP already safe |
| Q2 | Management-group scope in v1? | Product | No |
| Q3 | Use workload identity federation (WIF) from AKS instead of SP secret? | Security | Optional — SP first, WIF v2 |
| Q4 | Timeout | Platform | 10 min |
| Q5 | Skip `microsoft.classiccompute/*`? (pre-ARM) | Product | Yes — deprecated, noise |
| Q6 | `kind` column (e.g. `StorageV2` vs `BlobStorage`) — surface as sub_type? | Product | Yes — map to `properties.sub_type` so ingest sub-type promotion picks it up |

## 9. Non-goals

- AAD user/group enumeration.
- RBAC assignment graph.
- Policy / compliance evaluation results.
- Diagnostic settings.
- Cross-cloud (AWS assumed-role via Azure Arc) — separate task.

# #339 — GCP Connector (Cloud Asset Inventory)

- **Q/WS**: Q2 / WS-A
- **Status**: Pending — blocked on GCP sandbox service-account JSON
- **Seam**: `internal/app/connector/connector.go` (already defines `Connector` interface + `Registry`)
- **Related**: #340 Azure (same pattern), #327 AWS v1 (completed — scaffold only; this task reuses the Credentials struct it added)

## 1. Scope

**Ships:**
- `internal/app/connector/gcp/` package implementing `connector.Connector` for GCP.
- Resource enumeration via Cloud Asset Inventory (CAI) **search-all-resources** API (single endpoint covers 150+ GCP resource types).
- Mapping from GCP asset type → internal `asset.AssetType`.
- Integration test against a real GCP sandbox project (skipped in CI when `GCP_TEST_SA_JSON` env unset).
- Registration in `cmd/api/main.go` (or wherever the Registry is built) behind feature flag `connectors.gcp.enabled`.

**Does NOT ship:**
- Continuous/delta sync — v1 is pull-only, full enumeration every run. Delta via CAI Feed is a follow-up.
- Cross-org discovery — v1 assumes one project per Credentials (org-level is a follow-up).
- IAM policy graph — v1 only discovers resources, not IAM bindings.

## 2. External dependencies

| What | Why | Source |
|---|---|---|
| `cloud.google.com/go/asset/apiv1` | CAI client | `go get cloud.google.com/go/asset@latest` |
| `google.golang.org/api/option` | SA JSON auth | transitively pulled |
| Sandbox `service-account.json` | Integration test | user provides — stored in `ops/secrets/gcp-sandbox.json` (gitignored) |
| GCP project with CAI enabled | Sandbox target | `gcloud services enable cloudasset.googleapis.com` |
| IAM role `roles/cloudasset.viewer` on the SA | Read permission | user configures |

**Do NOT pull:** provider-specific resource libs (compute, storage, iam individually). CAI is the single entry — using per-service libs multiplies the code size 20×.

## 3. Data model

### 3.1 Credentials (already in `connector.Credentials`, re-using)

```go
type Credentials struct {
    ServiceAccountJSON string // raw JSON, decrypted by caller
    ProjectID          string // single project for v1
}
```

Validation rules the implementer MUST enforce on `Validate()`:
- `ServiceAccountJSON` parses as JSON with keys `type, project_id, private_key, client_email`.
- `ProjectID` matches `^[a-z][a-z0-9-]{4,28}[a-z0-9]$` (GCP project-id rule).
- If `ProjectID` set and differs from the JSON's `project_id` field → error (likely misconfiguration).

### 3.2 Per-asset properties (JSONB in `assets.properties`)

Keys use **snake_case** per project rule. Proposed:

```json
{
  "cloud_provider": "gcp",
  "gcp_project_id": "my-proj-123",
  "gcp_resource_name": "//compute.googleapis.com/projects/my-proj-123/zones/us-central1-a/instances/i-1",
  "gcp_asset_type": "compute.googleapis.com/Instance",
  "gcp_location": "us-central1-a",
  "gcp_labels": { "env": "prod" },
  "gcp_state": "RUNNING"
}
```

The top-level `Tags map[string]string` in `DiscoveredAsset` holds the same label map — UI consumes Tags, properties keeps the raw CAI record for debugging.

## 4. Public interface

```go
// internal/app/connector/gcp/gcp.go
package gcp

import (
    "context"

    "github.com/openctemio/api/internal/app/connector"
    "github.com/openctemio/api/pkg/domain/shared"
)

type Connector struct {
    // clientFactory lets tests inject a fake CAI client. nil → default.
    clientFactory func(ctx context.Context, saJSON string) (cai, error)
}

type cai interface {
    SearchAllResources(ctx context.Context, scope string) iter.Seq2[*assetpb.ResourceSearchResult, error]
    Close() error
}

func New() *Connector { /* uses real CAI client */ }

// Provider returns "gcp".
func (c *Connector) Provider() connector.Provider

// Validate hits CAI with a 0-result query to prove auth + IAM.
// Expected cost: 1 API call, ~200ms.
func (c *Connector) Validate(ctx context.Context, creds connector.Credentials) error

// Discover enumerates every resource in the project.
// Pagination: CAI returns up to 500 per page; iterator handles all pages.
// Context cancellation: honoured; partial result + error is the contract.
func (c *Connector) Discover(
    ctx context.Context,
    tenantID shared.ID,
    creds connector.Credentials,
) (*connector.DiscoveryResult, error)
```

## 5. Resource mapping

**Risk: this table is what breaks.** Implementer MUST cover at least these types in v1. Rows not in the table → `AssetType = asset.TypeUnknown` + properties carry the raw `gcp_asset_type` so operator can triage.

| GCP asset_type | Internal `asset.AssetType` | Name source | Notes |
|---|---|---|---|
| `compute.googleapis.com/Instance` | `TypeVirtualMachine` | resource short name | `additionalAttributes.networkInterfaces[].networkIP` → `properties.ip_address` |
| `compute.googleapis.com/Disk` | `TypeStorage` | resource short name | ignore boot disks if `source_instance` set (dedup w/ Instance) |
| `storage.googleapis.com/Bucket` | `TypeStorageBucket` | bucket name | check `labels.exposed=true` for public-hint |
| `sqladmin.googleapis.com/Instance` | `TypeDatabase` | instance name | `additionalAttributes.databaseVersion` → property |
| `container.googleapis.com/Cluster` | `TypeKubernetesCluster` | cluster name | endpoint → `properties.api_endpoint` |
| `iam.googleapis.com/ServiceAccount` | `TypeIdentity` | SA email | used by #350 git-host if WIF configured |
| `cloudfunctions.googleapis.com/CloudFunction` | `TypeServerlessFunction` | function name | runtime → property |
| `run.googleapis.com/Service` | `TypeServerlessService` | service name | URL → property |
| `pubsub.googleapis.com/Topic` | `TypeMessageQueue` | topic name | |
| `dns.googleapis.com/ManagedZone` | `TypeDNSZone` | zone name | |
| `bigquery.googleapis.com/Dataset` | `TypeDataWarehouse` | dataset id | |

**Pre-coding sanity check:** run `gcloud asset search-all-resources --scope=projects/$SANDBOX --format=json | jq '.[].assetType' | sort -u` against the sandbox to confirm the types that actually appear. Update the table before coding.

## 6. Test plan

### 6.1 Unit (`gcp_test.go`)
- `TestValidate_BadJSON_Rejected` — SA JSON missing required fields.
- `TestValidate_BadProjectID_Rejected` — invalid format.
- `TestValidate_ProjectIDMismatch_Rejected` — SA JSON project ≠ explicit ProjectID.
- `TestDiscover_MapsAllKnownTypes` — fake CAI returns 1 of each of the 11 types above, assert each produced the right `AssetType`.
- `TestDiscover_UnknownType_FallsBackToUnknown` — fake returns `fake.googleapis.com/Blorp`, assert `TypeUnknown` + raw type in properties.
- `TestDiscover_ContextCancellation` — fake blocks, ctx cancelled, assert partial result returned with ctx error in `Errors`.
- `TestDiscover_PerPageError_Continues` — fake page 2 errors, assert pages 1+3 land in result and error recorded.

### 6.2 Integration (`gcp_integration_test.go`, build-tagged)

```go
//go:build integration_gcp
// +build integration_gcp
```

Runs only when `GCP_TEST_SA_JSON` + `GCP_TEST_PROJECT_ID` env are set. Spins up 2-3 cheap resources (a tiny bucket + a disabled SA) via terraform under `tests/fixtures/gcp-sandbox/` then calls `Discover`. Asserts count ≥ fixture size and no mapping errors.

### 6.3 Smoke (`make test-gcp-sandbox`)
Runs the integration test against a pre-existing sandbox without creating resources. Used in CI weekly (not per-PR) because cost + noisy.

## 7. Rollout

1. Land the package + unit tests behind feature flag `connectors.gcp.enabled=false`. No registration in Registry yet.
2. Run integration test manually against sandbox — iterate on mapping table.
3. Flip flag to `true` in staging. One tenant opts in via Settings UI.
4. Watch `ctem_connector_discovery_duration_seconds{provider="gcp"}` and error rate for 1 week.
5. Enable for all tenants in prod.

Metric keys to add (in `internal/infra/metrics/connector.go`, which #327 already introduced):
- `ctem_connector_discovery_duration_seconds{provider,status}`
- `ctem_connector_assets_discovered_total{provider,asset_type}`
- `ctem_connector_errors_total{provider,error_class}`

## 8. Open questions

| # | Question | Who answers | Default if no answer |
|---|---|---|---|
| Q1 | Support `organization_id` scope (cross-project) in v1? | Product | No — defer to v2 |
| Q2 | Store SA JSON in `integration.credentials_encrypted` same column as AWS `role_arn`, or separate field? | Security | Same column, different discriminator |
| Q3 | On `Validate()`, do we list required IAM permissions in the error message? | Security | No — generic "auth failed", log specifics |
| Q4 | `Discover()` timeout — default 10 min, configurable? | Platform | 10 min hard cap |
| Q5 | Respect GCP labels `openctem/scope=exclude` to skip resources? | Product | Yes — implement in v1 |

## 9. Non-goals (write down so future PRs don't creep)

- **Delta sync via CAI Feed** — v2 task, requires Pub/Sub subscription wiring.
- **IAM policy graph** — separate "attack path" feature.
- **BigQuery table-level discovery** — datasets only in v1 (tables = 1000x volume).
- **Recommender API integration** — "this bucket is public" hints come from a different task.

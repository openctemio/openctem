# #349 — Kubernetes In-Cluster Connector

- **Q/WS**: Q3 / WS-A
- **Status**: Pending — blocked on dev kubeconfig + decision on in-cluster vs external-kubeconfig mode
- **Seam**: `internal/app/connector/connector.go`
- **Related**: #346 Endpoint-as-asset (completed — provides the `TypeEndpoint` class this connector will produce for Pods)

## 1. Scope

**Ships:**
- `internal/app/connector/kubernetes/` implementing `connector.Connector`.
- Two auth modes:
  - **In-cluster**: reads `/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt}` automatically when running as a Pod.
  - **External**: reads kubeconfig (base64-encoded in `Credentials.Token`) or bearer token + API URL.
- Enumerates: Pods, Services, Ingresses, Nodes, Namespaces, Deployments, StatefulSets, DaemonSets, CronJobs, ConfigMaps, Secrets (**metadata only — never values**), NetworkPolicies.
- Multi-namespace support — optional `Credentials.Namespace` filter; empty = all namespaces the SA can see.
- Integration test against `kind` or `minikube` — sandbox cluster launched in CI.

**Does NOT ship:**
- CRDs (Custom Resources) — separate task (each org has its own, requires discovery-dispatch).
- Pod exec / logs — read-only enumeration only.
- Helm release enumeration — follow-up via a `TypeHelmRelease` asset type.
- Admission-controller mode (reacting to apply events) — that's a separate "runtime telemetry" path, not a connector.

## 2. External dependencies

| What | Why | Source |
|---|---|---|
| `k8s.io/client-go@kubernetes-1.29.x` | K8s client | `go get k8s.io/client-go@v0.29.0` (pin to our cluster minor) |
| `k8s.io/apimachinery` | Shared types | transitive |
| Dev cluster | Integration test | `kind create cluster --name ctem-test` in CI |
| RBAC: `ClusterRole ctem-reader` with `get,list,watch` on every resource above | Read permission | ship as kubectl manifest in `deploy/kubernetes/ctem-reader-rbac.yaml` |

**Do NOT pull** `kubectl` CLI. Use the Go client directly; shelling to `kubectl` makes containerization harder and slows discovery.

## 3. Data model

### 3.1 Credentials (already in `connector.Credentials`)

```go
type Credentials struct {
    APIURL    string // e.g. https://kube.internal:6443 — empty means "use in-cluster config"
    Token     string // bearer token OR base64-encoded kubeconfig (see discriminator below)
    Namespace string // optional single-namespace scope
}
```

**Discriminator rule** (encode in a `kind` property on the integration, not in Credentials — keeps Credentials opaque):
- `in-cluster`: ignore APIURL/Token, use `rest.InClusterConfig()`.
- `bearer`: APIURL + Token (raw bearer), Token length 20-4096.
- `kubeconfig`: Token is base64-encoded YAML kubeconfig, APIURL unused.

### 3.2 Per-asset properties

```json
{
  "k8s_cluster_name": "prod-eu-1",
  "k8s_api_version": "v1.29.3",
  "k8s_namespace": "default",
  "k8s_kind": "Pod",
  "k8s_labels": { "app": "api" },
  "k8s_owner_refs": [ { "kind": "ReplicaSet", "name": "api-7d9c" } ]
}
```

Additional per-kind fields (keyed under `k8s_{kind}_*`):
- Pod: `pod_ip`, `node_name`, `container_images[]` (digest + tag).
- Service: `cluster_ip`, `external_ips[]`, `type` (ClusterIP/NodePort/LB), `load_balancer_ingress[]`.
- Ingress: `hosts[]`, `tls_hosts[]`.
- Node: `internal_ip`, `external_ip`, `os_image`, `kernel_version`, `kubelet_version`.
- Secret: **name only**, `type` (Opaque/kubernetes.io/tls/...). **Never `data`** even if SA has permission.

## 4. Public interface

```go
// internal/app/connector/kubernetes/k8s.go
package kubernetes

type Connector struct {
    clientFactory func(ctx context.Context, mode AuthMode, creds connector.Credentials) (kubernetes.Interface, error)
}

type AuthMode string
const (
    AuthInCluster  AuthMode = "in-cluster"
    AuthBearer     AuthMode = "bearer"
    AuthKubeconfig AuthMode = "kubeconfig"
)

func New() *Connector

func (c *Connector) Provider() connector.Provider // "kubernetes"
func (c *Connector) Validate(ctx context.Context, creds connector.Credentials) error
func (c *Connector) Discover(ctx context.Context, tenantID shared.ID, creds connector.Credentials) (*connector.DiscoveryResult, error)
```

### 4.1 Enumeration order (pin this)

Order matters for owner-ref backfill:
1. Namespaces (filter out `kube-*` unless `Credentials.Namespace=="kube-system"`).
2. Nodes (cluster-scoped, ignore namespace filter).
3. For each namespace: Deployments, StatefulSets, DaemonSets, CronJobs, ReplicaSets → then Pods → then Services / Ingresses → then ConfigMaps, Secrets, NetworkPolicies.

Parallelism: per-namespace goroutines, **capped at 8** — enumerating 500 namespaces in parallel will hit the apiserver's QPS limit (50 default).

### 4.2 Resource-version & pagination

Use `List` with `Limit: 500` + `Continue` token. Do NOT watch — this is a pull connector; the runtime-telemetry path (#343) handles events.

## 5. Resource mapping

| K8s kind | Internal `AssetType` | External ID |
|---|---|---|
| Node | `TypeHost` | `node/<cluster>/<name>` |
| Namespace | `TypeEnvironment` | `ns/<cluster>/<name>` |
| Pod | `TypeEndpoint` | `pod/<cluster>/<ns>/<uid>` |
| Service | `TypeNetworkService` | `svc/<cluster>/<ns>/<name>` |
| Ingress | `TypeIngress` | `ing/<cluster>/<ns>/<name>` |
| Deployment / StatefulSet / DaemonSet | `TypeWorkload` | `<kind>/<cluster>/<ns>/<name>` |
| CronJob | `TypeScheduledTask` | `cj/<cluster>/<ns>/<name>` |
| ConfigMap | `TypeConfiguration` | `cm/<cluster>/<ns>/<name>` |
| Secret | `TypeSecret` | `sec/<cluster>/<ns>/<name>` |
| NetworkPolicy | `TypeNetworkPolicy` | `netpol/<cluster>/<ns>/<name>` |

**Dedup note:** Pod ExternalID uses UID not name — pods restart and get new UIDs. Asset resolver (RFC-001) uses `cluster + namespace + workload-owner` as the stable identity key for Pods, so rolling restarts don't create thousands of ghost assets. Implementer: verify RFC-001 has a rule for this before coding — if not, add one.

## 6. Test plan

### 6.1 Unit
- `TestAuthModeDetection` — discriminator resolves correctly for each `kind`.
- `TestValidate_InClusterMissingFiles_Rejected` — not running in a pod → error.
- `TestValidate_BearerBadURL_Rejected`.
- `TestDiscover_AllKinds_Mapped` — fake client returns one of each kind.
- `TestDiscover_NamespaceFilter_Honoured`.
- `TestDiscover_SecretValueNeverInProperties` — fake Secret has `data.foo=base64(...)`, assert discovered asset has `k8s_kind=Secret` but NO `data` field anywhere in properties.
- `TestDiscover_PodOwnerRefBackfill` — Pod with owner ReplicaSet → ReplicaSet with owner Deployment → assert Pod's `k8s_owner_refs` resolves all the way to Deployment.
- `TestDiscover_Pagination_Continues`.
- `TestDiscover_ApiserverThrottling_BackoffHonoured` — fake returns 429 → retry with Retry-After.

### 6.2 Integration
Build tag `integration_k8s`. `kind create cluster`, apply `tests/fixtures/k8s-sandbox/*.yaml` (1 Pod, 1 Svc, 1 Ingress, 1 Secret, 1 NetworkPolicy), run Discover, assert.

## 7. Rollout

1. Unit tests land first (no cluster needed).
2. Integration test behind `integration_k8s` tag — CI runs it on a scheduled workflow, not per-PR.
3. Feature flag `connectors.kubernetes.enabled`. Staging tenant opts in → watches metrics 1 week.
4. Ship RBAC manifest with release notes: "Before enabling, apply `deploy/kubernetes/ctem-reader-rbac.yaml` to your cluster."

## 8. Open questions

| # | Question | Who answers | Default |
|---|---|---|---|
| Q1 | Secrets — enumerate names or skip entirely? | Security | Enumerate names (defensive visibility). Hard-reject enumerating `data`. |
| Q2 | Custom Resources (CRDs) — v1 scope? | Product | No — v2 task |
| Q3 | Multi-cluster in one integration? | Product | No — one integration per cluster |
| Q4 | Use `metav1.Table` API (printer columns) to reduce bytes, or full objects? | Platform | Full objects — we need labels/owner-refs which Table drops |
| Q5 | Respect `openctem.io/scope=exclude` annotation? | Product | Yes |
| Q6 | Audit: log every Discover call to k8s apiserver audit? | Security | SA is logged by apiserver already; no extra work |

## 9. Non-goals

- Write operations. This is a **read-only** connector. Any "apply manifest" style work is a separate executor task.
- OPA / Kyverno policy eval integration.
- Container image vulnerability scanning — that's a different task (image scanner consumes the discovered images).
- Service mesh (Istio / Linkerd) CRDs.

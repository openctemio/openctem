# Attack surface posture score

One grade from **A** to **F** for the external attack surface of an
organization and of each of its root domains, with what each category of
issue takes away, what to fix to reach the next grade, and how much fixing
the issues on assets of each criticality would gain. Part of EASM
([RFC-036](../rfcs/RFC-036-easm.md)); the figures follow the dashboard rule
that numbers are precomputed into tables and read with the reader's scope.

| Part | Where |
|---|---|
| Formula and its constants | `pkg/domain/posture/posture.go` |
| Facts and state | `easm_posture_assets`, `easm_posture_state` (migration `easm_posture`) |
| Rebuild, reads | `internal/infra/postgres/easm_posture_repository.go` |
| Service (read, Recalculate now, schedule, refresher) | `internal/app/posture/service.go` |
| Routes | `GET/POST/PUT /api/v1/attack-surface/posture...` (`easm_posture_handler.go`) |
| Refresher | controller `easm-posture` (every minute, one replica) |
| Dashboard widget | metric `surface.posture` (shape and visualization `posture`) |
| Web | Attack surface overview card, `/attack-surface/posture` |

## What counts

**Surface assets** are the attributed inventory (no `discovered`,
`needs_review`, `candidate` or `rejected` attribution record), not deleted,
not program-only, status `active` or `stale`, of type domain, subdomain,
IP address or certificate, or of any other type marked internet accessible.

**Issues**, on surface assets only:

| Category | Issues | Counted |
|---|---|---|
| `vulnerabilities` | open, published findings (dashboard fact F1, lens open), pentest findings left out (they stay with their campaign) | per finding |
| `hijackable_subdomains` | active `dangling_cname`, `dangling_ns`, `subdomain_takeover` exposures | one per asset, its worst |
| `exposed_services` | active `port_open`, `service_detected`, `api_exposed`, `web_interface_exposed`, `mcp_server_exposed` | per exposure |
| `cloud_storage` | active `bucket_public` | per exposure |
| `misconfiguration` | active `ssl_issue`, `certificate_expiring`, `certificate_expired`, `email_security_weak`, `header_missing`, `misconfiguration`, `repo_public` | per exposure |
| `suspicious_activity` | active `credential_leaked`, `lookalike_domain`, `sensitive_data_exposed`, `mail_server_blocklisted` | per exposure |

Exposure events projected from findings (sources `secret_scan` and
`misconfig_scan`) are left out: the finding already counts. Exposures with
no asset (a leaked credential of the organization, a lookalike domain) are
kept in one row with the all-zero asset id; only a reader who sees the whole
organization counts it.

## Formula

Each issue has **points** by severity: critical 10, high 5, medium 2, low
0.5, informational 0. A finding whose CVE is known exploited counts double.
All points of an asset are multiplied by its **criticality**: critical (and
every crown jewel) 2, high 1.5, medium 1, low 0.5.

For a set of `N` surface assets with `P(c)` points in category `c`:

```
deduction(c) = Max(c) * P(c) / (P(c) + HalfPerAsset(c) * max(N, 10))
score        = floor(100 - sum of deductions)
grade        = A >= 90, B >= 80, C >= 70, D >= 60, F below
```

| Category | Max | HalfPerAsset |
|---|---|---|
| vulnerabilities | 35 | 2.0 |
| hijackable subdomains | 15 | 0.2 |
| exposed services | 15 | 1.0 |
| cloud storage | 10 | 0.2 |
| misconfiguration | 15 | 1.0 |
| suspicious activity | 10 | 0.5 |

- `Max` values add up to 100. A category takes half its `Max` when it has
  `HalfPerAsset` points per surface asset, and never all of it, so fixing
  any issue raises the score and one category cannot hide another.
- Scaling by the surface size keeps a large estate from being graded F for
  the number of its assets; `max(N, 10)` keeps a handful of assets from
  being graded on one issue alone.
- No surface asset is **not measured**: no grade, never an A by default.

Worked examples: one confirmed takeover (critical, 10 points) on 100 assets
takes `15 * 10 / (10 + 20) = 5`, score 95, A. One critical vulnerability on
a medium asset of a 10-asset estate takes `35 * 10 / (10 + 20) = 11.7`,
score 88, B.

## Explaining the score

- **Per category**: points, issues, the deduction and the score once every
  issue of the category is fixed.
- **Fix plan to the next grade**: the (asset, category) items of the read
  ordered by `points * Max / HalfPerAsset` (score gained per point, which does
  not depend on the surface size, so SQL can order them), walked until the
  score reaches the next grade's floor; at most 25 steps from the 200 most
  urgent items. Each step shows the score after it.
- **Risk reduction by asset criticality**: per criticality level, its share
  of all points and the score points fixing every issue on those assets
  would add.
- **Root domains**: the registrable domain (public suffix list) of each
  surface asset's name; every root is scored on its own assets with the same
  formula, worst first (at most 100 rows). Addresses and issues without an
  asset count in the organization's score only.

## Precomputation and refresh

- `easm_posture_assets` holds one row per surface asset: root domain,
  effective criticality, weighted points and issue counts per category.
  A **rebuild** replaces an organization's rows in one transaction (a
  per-organization advisory lock: one rebuild at a time, statement timeout
  2 minutes) from `assets`, `asset_attributions`, `dash_asset_state` and
  `exposure_events`.
- `easm_posture_state` holds the schedule (`manual`, `1h`, `6h` default,
  `24h`), the next refresh, the last computation (time, duration, surface
  size, organization-wide score and grade, the previous ones) and the last
  failure. The state row is created on the first read (page or widget), due
  at once, so organizations that never look at the posture cost nothing.
- **Refresher** (`easm-posture`, every minute, exclusive): claims due
  organizations with `FOR UPDATE SKIP LOCKED` and a 10-minute lease, rebuilds
  them, stores the result and the next time. A failure keeps the last facts,
  records `refresh_failed` and retries in 15 minutes (not on manual).
- **Recalculate now**: rebuilds synchronously, at most once every 5 minutes
  per organization (429 with `Retry-After`; one atomic statement), 409 while a
  rebuild runs. Audited `easm_posture.recalculated`.
- **Schedule**: `PUT .../schedule`, audited `easm_posture.schedule_changed`.
- Freshness: every response carries `computed_at`, `next_refresh_at`,
  `building` (no computation yet) and `stale` (last refresh failed or older
  than twice the schedule).

## Routes and authorization

| Route | Permission | Notes |
|---|---|---|
| `GET /api/v1/attack-surface/posture` | `assets:read` | list query contract registry `attack_surface_posture` (`root_domain`, `criticality`, `asset_id` filters) |
| `POST /api/v1/attack-surface/posture/refresh` | `assets:write` | budgeted, audited |
| `PUT /api/v1/attack-surface/posture/schedule` | `settings:write` | `manual`, `1h`, `6h`, `24h`; audited |

All behind the `attack_surface` module gate. A dashboard widget of
`surface.posture` needs `assets:read` on a personal read (otherwise
`unsupported` / `forbidden`).

## Scope and isolation

- The tenant comes from the authenticated caller. The read compiles a
  filter through `filterspec.Compile` with the caller's actor, so the WHERE
  always starts with `p.tenant_id = $1` and, for a restricted caller, the
  data scope on `p.asset_id`; facts of deleted or program-only assets are
  skipped at read time (`posture.LiveSQL`).
- A **scoped** reader's score, plan, reductions and root domains are
  computed from the assets they may see only: they never learn how many
  issues exist elsewhere. The row of issues without an asset never matches a
  scope. The organization-wide previous score is shown only to an unscoped,
  unfiltered read. A member with no scope row has no grade.
- The dashboard widget reads with the server-built `ReadScope`: personal
  dashboards with the owner's scope, organization dashboards organization
  wide, like every widget.
- Plan steps name an asset only when the reader may see it (the step comes
  from the same scoped read).
- The rebuild runs as the platform for one organization; every statement is
  pinned to that tenant. Cross-tenant work is only the refresher's claim
  (`ClaimDueForPlatform`), which reads tenant ids and nothing else.

## Threat model

| Threat | Mitigation |
|---|---|
| A scoped member learns the organization's issue counts | sums are computed per read with the data scope compiled in; no organization total or trend for scoped reads; asset-less issues only for unscoped reads |
| Another tenant's issues count | tenant predicate first in every read; rebuild queries pinned to one tenant; DB test with a second tenant |
| Recalculate now used to load the database | 5-minute per-organization budget in one atomic statement; one rebuild per organization at a time (advisory lock); 2-minute statement timeout |
| A gamed or noisy producer inflates a category | each category is bounded by its `Max`; hijackable issues count once per asset; projections of findings are not counted twice |
| A deleted or rejected asset keeps lowering the score | rejected and unattributed assets are not surface; deleted assets are skipped at read time and dropped at the next rebuild |

## Tests

- `pkg/domain/posture/posture_test.go`: weights, worked examples, monotony,
  grades, fix plan, reductions, category mapping, root domains.
- `internal/app/posture/service_test.go`: budget, failure retry, busy,
  schedules, refresher, scope compiled into the read, fail closed without an
  enforcer.
- `internal/app/dashboard/widgets/posture_test.go`: widget states and value,
  server-built scope, permission.
- `internal/infra/http/routes/posture_scope_db_test.go` (Postgres): owner,
  scoped member and member without scope; deleted, rejected and another
  tenant's assets never count; projections not counted twice; root filter
  outside the scope; Recalculate budget; schedule validation.

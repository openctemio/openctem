# RFC-021 — Customizable dashboards (Tenable-style widgets)

- Status: **Proposed** — design for review; to be built in phased PRs that reference this RFC.
- Area: UI dashboards + a small per-user persistence surface in `api`.
- Related: the existing CTEM/Classic dashboards (`ui/src/features/dashboard`), the per-user notification/preferences pattern, RFC-017 (CTEM prioritization surfacing — the signals widgets show), and the "custom field query" idea (a future widget data-source — see §7).

## 1. Goal

Let each user **compose their own dashboard** — like Tenable.sc/Tenable.io: pick
widgets from a catalog, arrange/resize/remove them on a grid, and have that
layout **persist per user**. Today OpenCTEM has two *fixed* dashboards (a CTEM
view and a Classic view, toggled) plus a fixed `/my-work` personal view — none
are user-composable.

Non-goal (this RFC): an arbitrary "any field → any chart" query-and-viz builder.
That is powerful but huge; we get ~80% of Tenable's value from a **curated widget
catalog** first, and leave per-widget custom queries to a later phase (§7).

## 2. The load-bearing decision: reuse existing cards as the widget catalog

We already have the visual components a dashboard needs — they're just wired into
two hardcoded layouts. The catalog is those cards, wrapped as **widgets**:

| Widget | Backed by (existing) |
|--------|----------------------|
| Findings by severity | dashboard stats |
| SLA breach / aging | `useFindingsApi` sla_status |
| Risk trend | risk-trend hook |
| MTTR | `mttr-card` |
| Open findings / quick stats | `quick-stat` |
| Program health · CTEM maturity · Data quality | `program-health-view` / maturity / `data-quality-view` |
| Top risky assets | asset stats |
| Threat intel (EPSS/KEV) · Detections | threat-intel / IOC matches |
| **My Work** (assigned to me) | the `assigned_to_me` finding filter |

So the catalog is **not new visualizations** — it's a registry over components
that already exist and already fetch their own data.

## 3. Model

```
Dashboard (per user, per tenant)
  ├─ id, name, is_default
  └─ widgets: [ { widgetType, x, y, w, h, config? } ]
```

- **WidgetType** — a string key into a frontend **widget registry**
  (`WIDGET_REGISTRY[type] = { title, component, defaultSize, minSize, requiredPermission?, requiredModule? }`).
  A widget the user can't see (missing permission or disabled module) is hidden
  from the catalog and skipped on render — reusing the existing `Can` / module
  gates so a custom dashboard can never leak a gated widget.
- **Layout** — a responsive grid (12-col). Position/size per widget.
- **config** (optional, reserved) — per-widget options (time range, severity
  filter). Empty in Phase 1; the seam for §7.

## 4. Persistence (per-user, server-side)

A user's dashboards must follow them across devices, so store server-side (not
localStorage). Minimal surface, mirroring existing per-user features:

- Migration: `user_dashboards (id, tenant_id, user_id, name, is_default, layout jsonb, created_at, updated_at)` with a unique `(tenant_id, user_id, name)` and a partial unique index enforcing one default per (tenant,user). `layout` holds the widgets array (bounded size — validate widget count ≤ N and known types).
- Endpoints (JWT, self-scoped — a user manages only their own dashboards):
  `GET /api/v1/me/dashboards`, `POST /api/v1/me/dashboards`,
  `PUT /api/v1/me/dashboards/{id}`, `DELETE /api/v1/me/dashboards/{id}`.
  These live under the already-allowlisted `/me/` self-scope (see the route-authz
  coverage test), so no new gate class.
- Tenant/user come from the auth context, never the body (tenant isolation by construction).

## 5. UX

- The dashboard page gets a **dashboard switcher** (My CTEM · Classic · + the
  user's saved dashboards) + **New dashboard** / **Edit**.
- **Edit mode**: an "Add widget" catalog drawer; drag to reorder, resize handles,
  remove (×). **Save** persists the layout; **Cancel** reverts.
- A user with no custom dashboard sees today's default (CTEM view) unchanged —
  **fully backward compatible**; customization is opt-in.
- Empty custom dashboard → a helpful "Add your first widget" state.

## 6. Phases

- **Phase 1 (MVP)** — widget registry over existing cards; `user_dashboards`
  table + `/me/dashboards` CRUD; grid render + add/remove/reorder/resize; switcher;
  permission/module-aware catalog. No per-widget config yet. Delivers a real
  customizable dashboard.
- **Phase 2** — per-widget `config` (time range, severity/status filter, tenant vs
  "assigned to me" scope), widget-level refresh, duplicate-dashboard, set-default.
- **Phase 3** — shareable/tenant **template** dashboards an admin can publish; a
  starter gallery (SOC, Exec, AppSec, VM).
- **Phase 4 (ties to the custom-query idea)** — a "Custom query" widget whose data
  source is a saved advanced query over finding/asset fields (field/op/value,
  AND/OR). This is where the Tenable-style **custom field query** lands, reusing
  `FindingFilter`/`asset.Filter` + the existing CTEM facet filters.

## 7. Why a grid lib, and which

Use a small, dependency-light React grid (e.g. a self-contained CSS-grid + a
lightweight drag/resize) rather than a heavy external one, to respect the
Artifact-style no-bloat house rule and keep bundle size down. Evaluate in Phase 1;
fall back to a simple reorder-only (no free resize) if drag-resize proves heavy —
reorder + fixed sizes still delivers the core value.

## 8. Guardrails (avoid the facade trap)

- Every widget in the catalog must render **real** data on day one — no "coming
  soon" tiles. A widget with no backing data doesn't ship.
- The catalog is permission/module-filtered so a custom dashboard can't surface a
  widget the user couldn't otherwise see.
- Layout payload is validated + size-bounded server-side (unknown widget types
  rejected) to keep the JSONB honest and DoS-safe.

## 9. Open questions

1. One default dashboard per user, or per-role starter templates seeded on first login?
2. Do we replace the CTEM/Classic toggle with "saved dashboards" outright, or keep them as built-in, non-deletable entries in the switcher? (Proposed: keep as built-ins.)
3. Grid: free resize vs reorder-only for Phase 1 (bundle-size tradeoff).

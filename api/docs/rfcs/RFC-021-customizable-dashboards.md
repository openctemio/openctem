# RFC-021 — Customizable dashboards (widgets)

- Status: **Phase 1 implemented** — `/api/v1/me/dashboards` CRUD + set-default, the widget registry and starter templates (`web/src/features/dashboards`); per-widget config (rest of Phase 2), tenant-published templates (Phase 3) and the custom-query widget (Phase 4) not built.
- Area: UI dashboards + a small per-user persistence surface in `api`.
- Related: the existing CTEM/Classic dashboards (`web/src/features/dashboard`), the per-user notification/preferences pattern, RFC-017 (CTEM prioritization surfacing — the signals widgets show), and the "custom field query" idea (a future widget data-source — see §7).

## 1. Goal

Let each user **compose their own dashboard**: pick
widgets from a catalog, arrange/resize/remove them on a grid, and have that
layout **persist per user**. Today OpenCTEM has two *fixed* dashboards (a CTEM
view and a Classic view, toggled) plus a fixed `/my-work` personal view — none
are user-composable.

Non-goal (this RFC): an arbitrary "any field → any chart" query-and-viz builder.
That is powerful but huge; a **curated widget catalog** delivers most of the
value first, and leave per-widget custom queries to a later phase (§7).

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

### 2.1 Terminology — "widget" ≡ "component"

The tile a user places on a dashboard is a **widget** (this RFC's term). Users
also call it a **"component"**; we treat the words as synonyms in the UI.
(In code it's a React component that renders the widget — distinct meaning; we say
"widget" for the dashboard tile to avoid the collision.)

A widget is three things:

```
Widget (= component) = Data source (query/filter)  +  Visualization  +  Config
```

- **Data source / query** — what data it pulls (e.g. `findings: severity=critical,
  assigned_to_me, last 30d`). "Customizing a tile by applying a query" = editing
  this.
- **Visualization** — how it shows: single stat, bar/pie, table, trend line, or a
  matrix (rows × columns of counts).
- **Config** — title, time range, scope (tenant / assigned-to-me / BU / asset group).

That yields **two kinds of widget**, both first-class:

1. **Catalog widget** (prebuilt) — a curated card (severity, SLA, MTTR, …) with a
   fixed query + viz. Drop-in, zero config. **Phase 1.**
2. **Query-driven / custom component** — the user *picks a data source, applies a
   query/filter, and chooses the visualization*.
   This is where the **custom-field query** idea lands (a saved advanced query over
   finding/asset fields becomes a widget's data source). **Phase 2 config →
   Phase 4 full query builder** (§7).

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

- The dashboard page gets a **dashboard switcher** (built-in views · template
  gallery · the user's saved dashboards) + **New dashboard** / **Edit**.
- **Edit mode**: an "Add widget" catalog drawer; drag to reorder, resize handles,
  remove (×). **Save** persists the layout; **Cancel** reverts.
- A user with no custom dashboard sees today's default (CTEM view) unchanged —
  **fully backward compatible**; customization is opt-in.
- Empty custom dashboard → a helpful "Add your first widget" state.

## 6. Templates-first: a starter gallery to copy from

**The entry point is a gallery of curated template dashboards, not a blank grid.**
Most users don't want to build a dashboard from scratch — they want a good one for
their job that they can then tweak. So:

- Built-in **templates** are code-defined, read-only layouts (a name + a widget
  list with positions). They always exist, can't be edited or deleted, and render
  live data like any dashboard.
- **"Use this template" / Copy** clones a template into a new **personal**
  dashboard the user then edits freely (add/remove/reorder/resize, rename).
- **New blank** creates an empty personal dashboard for power users.
- **Duplicate** clones any personal dashboard; **Set default** picks the landing one.

This makes templates immediately valuable AND the fastest path to a custom one —
so the built-in gallery ships in **Phase 1**, not later.

### 6.1 The starter gallery (sample dashboards — think broad)

Each is a curated layout over the Phase-1 widget catalog (§2), sized for its
audience. All are permission/module-filtered per viewer, so a widget the user
can't see is dropped from the copy.

| Template | Audience / job-to-be-done | Widgets |
|----------|---------------------------|---------|
| **Executive / CISO** | risk posture at a glance | risk-score trend · open criticals · MTTR · SLA compliance % · CTEM maturity · program health · top business units by risk |
| **SOC / Triage** | work the incoming queue | new findings · by severity · assigned-to-me · detections (IOC matches) · threat-intel KEV/EPSS movers · overdue SLA |
| **Vulnerability Management** | run the VM program | findings by severity+status · scan coverage · remediation-campaign progress · SLA breach board · aging buckets · reopened/recurring |
| **AppSec / Developer** | code-side exposure | my assigned findings · findings by repo/component · SAST/SCA/secrets exposures · SBOM vulnerabilities · CI-gate status |
| **My Work** (asset owner / dev) | just my responsibilities | assigned-to-me summary · my overdue SLA · my assets at risk · my top findings queue |
| **Compliance** | control & audit posture | framework coverage · control-testing results · exceptions/suppressions · evidence freshness |
| **Pentest / Offensive** | validation & attack paths | pentest campaigns · findings by MITRE technique · attack paths · exposure chains · validation results |
| **CTEM Program** | drive the 5-stage loop | CTEM cycle status · per-stage coverage (scoping→mobilization) · maturity trend · data-quality scorecard |
| **Attack Surface** | what's exposed externally | internet-facing assets · newly-discovered subdomains/certs · crown jewels at risk · exposure by type |

New personas are just new entries in the template registry — no schema change.

### 6.2 Flexibility axes (every dashboard, any template or custom)

- **Scope** (per dashboard, P2 config): tenant-wide · *assigned to me* · a chosen
  **business unit** · a chosen **asset group**. One layout, re-pointable — a lead
  and a developer can use the same template scoped differently.
- **Time range** per dashboard (7 / 30 / 90d / custom).
- **Compose freely**: copy a template → add/remove any catalog widget → rename →
  set default. Keep several dashboards and switch.
- **Share up (P3)**: a tenant admin promotes a personal dashboard to a **tenant
  template** so it joins everyone's gallery (org-standard SOC/Exec views).
- **Deep-link**: a dashboard/widget links into the pre-filtered list it summarizes
  (numbers ⇔ drill-down always agree, like `/my-work` already does).

## 7. Phases

- **Phase 1 (MVP)** — widget registry over existing cards; the **built-in template
  gallery (§6.1) + "copy to personal"**; `user_dashboards` table + `/me/dashboards`
  CRUD; grid render + add/remove/reorder/resize; switcher; permission/module-aware
  catalog. Templates + copy are the headline of P1 (no per-widget config yet).
  Delivers a real customizable dashboard people can start from.
- **Phase 2** — per-widget `config` (time range, severity/status filter, tenant vs
  "assigned to me" scope), widget-level refresh, duplicate-dashboard, set-default.
- **Phase 3** — shareable/tenant **template** dashboards an admin can publish; a
  starter gallery (SOC, Exec, AppSec, VM).
- **Phase 4 (ties to the custom-query idea)** — a "Custom query" widget whose data
  source is a saved advanced query over finding/asset fields (field/op/value,
  AND/OR). This is where the **custom field query** lands, reusing
  `FindingFilter`/`asset.Filter` + the existing CTEM facet filters.

## 8. Why a grid lib, and which

Use a small, dependency-light React grid (e.g. a self-contained CSS-grid + a
lightweight drag/resize) rather than a heavy external one, to respect the
no-bloat house rule and keep bundle size down. Evaluate in Phase 1;
fall back to a simple reorder-only (no free resize) if drag-resize proves heavy —
reorder + fixed sizes still delivers the core value.

## 9. Guardrails (avoid the facade trap)

- Every widget in the catalog must render **real** data on day one — no "coming
  soon" tiles. A widget with no backing data doesn't ship.
- The catalog is permission/module-filtered so a custom dashboard can't surface a
  widget the user couldn't otherwise see.
- Layout payload is validated + size-bounded server-side (unknown widget types
  rejected) to keep the JSONB honest and DoS-safe.

## 10. Open questions

1. One default dashboard per user, or per-role starter templates seeded on first login?
2. Do we replace the CTEM/Classic toggle with "saved dashboards" outright, or keep them as built-in, non-deletable entries in the switcher? (Proposed: keep as built-ins.)
3. Grid: free resize vs reorder-only for Phase 1 (bundle-size tradeoff).

# Inventory and integrations, learning from ProjectDiscovery Cloud

OpenCTEM web UI · 2026-10-03 · gap analysis and UI plan. Approved 2026-10-03 (D1–D13); not yet implemented.
Basis: `openctemio/openctem` `develop` @ `e04bfb35`. The sensor and SDK findings come from read-only greps of the `agent` and `sdk-go` repositories.

> **Status (2026-10-03): D1–D13 approved by the owner as recommended** (§8). D14–D16 (design system, §10) are open. Implementation starts with wave 1 in separate PRs.

The owner likes ProjectDiscovery Cloud (PD) for its minimal UI: a short nav, an inventory where each row reads like a card, and an integrations catalog. This document maps each PD pattern to what OpenCTEM has today, lists the gaps, and proposes a phased UI plan that follows the [UI style contract](../ui-style-contract.md), the [Scoping IA](./scoping-ia-2026-10.md) and the Settings IA (2026-10-01).

Related work:

- **RFC-036 (EASM)** already plans the data side: httpx/tlsx fields kept, optional gowitness screenshots, 30-day screenshot retention, and an Inventory tab. See `api/docs/rfcs/RFC-036-easm.md` §6.6, §6.11 and §12.3 O7.
- **The Asset Inventory v2 RFC**, being written in parallel, owns the data model: filter DSL, facets API, labels, dynamic groups, exclusions, policies, screenshots and change detection. Where this document needs an API, it states the UI's requirement and defers the shape to that RFC.
  - That RFC is called "RFC-041" in coordination. Open PR #871 already uses RFC-041 for "API path design", so one of the two needs a new number.

A mock of the proposed Inventory and Integrations screens was built alongside this document (HTML, OpenCTEM tokens from `web/src/styles/theme.css`, example.com data). It is not committed; see §9.

---

## TL;DR

- **Most of the data PD shows already reaches our API, and the web shows almost none of it.**
  - httpx status, title, web server, technologies, content length, CDN and IP are stored on `service` assets as `properties.*`.
  - The typed pages read **different keys**: `metadata.technology` instead of `technologies`, `metadata.server` instead of `web_server`, and flat `port`/`asn`/`cert_*` where ingest writes nested `service.*`, `ip_address.*` and `certificate.*`. So real scan data is invisible except in a generic key/value section of the drawer.
  - Fixing these readers is the cheapest, highest-value change in this document (**P0**).
- **What really is missing:**
  - favicon hash, ASN, CNAME and the TLS certificate from httpx: they are parsed by sdk-go, then dropped at `core.LiveHost`;
  - screenshots: none anywhere;
  - a per-value facet count endpoint;
  - group-by on assets;
  - scanning from a selection or a group (the bulk bar has no scan);
  - a bulk label API;
  - an integrations **catalog**: today there are category cards that link to per-category pages, with configuration in dialogs;
  - OAuth for any integration;
  - every cloud connector.
- **The PD row is achievable inside our contract.** It becomes **one `DataTable`** with rich cells (service, screenshot, technologies, TLS, last seen), not a card list, so sort, selection, the bulk bar, the drawer and pagination keep working. PD's "group-by chips" become our existing **group-by select + `rowGroups`** (Findings and Sensors already use them). The group header gets PD's "N services", **Scan** and **Export**.
- **Facet counts must be honest.** `FacetPanel` deliberately shows no per-option counts, because counts that ignore the other active filters mislead (`web/src/features/shared/components/facet-filter-panel.tsx:15-16`).
  - PD-style counts are fine only if the API computes them **disjunctively**: each facet's counts are taken with every _other_ active filter applied.
  - That is a hard requirement on the facets endpoint (§5.2).
- **Integrations:** move to one catalog at `/settings/integrations`:
  - tabs Available | Connected;
  - a category select;
  - a card grid, where clicking a card opens a **`DetailSheet`** with a shared **`Stepper`**;
  - **only providers with a working client are connectable**; planned ones are shown as "Planned" with no button.
  - Jira gets OAuth 2.0 (3LO) as the recommended method, with per-tenant encrypted tokens and refresh.
- **Dashboard and settings:**
  - Take PD's "newest detections" and turn it into a tenant question: "new checks: am I affected?".
  - A security score only with a visible formula and a "not enough data" state. PD shows 100 "Excellent" with nothing scanned.
  - Settings gains Scan egress IPs, Discovery sources, Severity overrides and Retest & regressions inside the existing 6-group IA (§2.10).
- **Design system (§10):** research 07 mapped to the style contract.
  - Adopt: disjunctive facets with range sliders, density modes, saved views, a findings Inbox, merge/unmerge, conditional snooze, drill-down tiles and the three empty-state kinds.
  - Reject: industry benchmarks.
  - The contract edits are proposed as a diff, not applied.
- **Nav:** do not copy PD's flat nav wholesale. It is short because PD has no CTEM stages.
  - Keep the approved Scoping and Settings IA.
  - Turn on the existing badge counts (behind a flag today) with honest sources only.
  - Add a "+ Create" menu.

---

## 1. PD patterns, as described by the owner

| #   | Area         | PD pattern                                                                                                                                                                                                                                                                                                                                                                                                                                |
| --- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| N1  | Nav          | Team switcher; "+ Create" dropdown; ~10 flat items with badge counts; Settings / Help / Logout at the bottom; dark theme; monospace hostnames                                                                                                                                                                                                                                                                                             |
| I1  | Inventory    | Tabs Overview, Asset Groups (dynamic groups only), Inventory, Domains, Screenshots, Policies                                                                                                                                                                                                                                                                                                                                              |
| I2  | Inventory    | Header: one primary "Start Vulnerability Scan", secondary "Export"                                                                                                                                                                                                                                                                                                                                                                        |
| I3  | Filters      | Search plus "Add Filters": a faceted menu (Response, Labels, Domain, Host, Port, Technology, Title, CNAME, IP, Content length, Status, Web server, Favicon, Has screenshot / favicon / technology). Each value submenu has counts, checkboxes, search and "Apply (n)". There is also an "Ask AI" entry                                                                                                                                    |
| I4  | Group-by     | Chips: All services, Technologies, Ports, Labels, Domains, More (Hosts, IPs, CNAME, Status codes, Titles, Web servers); sort; time range; refresh                                                                                                                                                                                                                                                                                         |
| I5  | Row          | Service card: favicon + `host:port` (mono); status chip coloured by class (2xx green, 3xx blue, 4xx orange/red); "Issues found" chip; ASN and IP chips with "+7" overflow; CNAME with "+4"; inline label chips + "Add labels"; screenshot thumbnail with the title under it (or a placeholder); technology chips or an explicit "No technologies"; TLS chip (expired N days ago / N days to expiry) + issuer + SAN; relative time; delete |
| I6  | Tech view    | One row per technology: icon, mono name, "56 Services", category chip(s) with "+1 more", one-line description, expand to its services                                                                                                                                                                                                                                                                                                     |
| I7  | Group view   | Header per value (port 443, label, domain, host): "N Services", **Scan this group**, Export, collapse; expanded group pages its rows ("Showing 1–3 of 3", prev/next); the other groups are collapsed                                                                                                                                                                                                                                      |
| I8  | Search       | The placeholder follows the group-by mode ("Search technologies…", "Search ports…")                                                                                                                                                                                                                                                                                                                                                       |
| I9  | Bulk         | Filter, then an action-bar "Label" button; "Save Filter" creates a dynamic group                                                                                                                                                                                                                                                                                                                                                          |
| I10 | Policies     | AND conditions; actions add/remove label, notify, delete; scope "future only" or "existing + future"                                                                                                                                                                                                                                                                                                                                      |
| I11 | Exclusions   | One pattern per line, `*` wildcards and CIDR                                                                                                                                                                                                                                                                                                                                                                                              |
| G1  | Integrations | Tabs Available (18) and Connected (1); search; category filter; card grid (logo, name, category chip, one line)                                                                                                                                                                                                                                                                                                                           |
| G2  | Integrations | Card opens a right panel "Configure Jira" with a 3-step stepper. The auth method is two option cards, "OAuth (Recommended)" and "API Token (Legacy)", followed by "Authenticate with Jira"                                                                                                                                                                                                                                                |
| G3  | Integrations | The Connected tab lists rows: icon, name, last modified, category chips, Edit, Delete                                                                                                                                                                                                                                                                                                                                                     |
| I12 | Group lenses | IPs, CNAME, Status codes, Titles and Web servers groups start **collapsed** ("203.0.113.x · 26 services", "nginx · 60", "403 Forbidden · 23"). The "More" dropdown shows the active mode's name ("CNAME ▾"), and the search placeholder follows it                                                                                                                                                                                        |
| I13 | Row          | Status chip shows the redirect chain ("301, 200 OK", green when the final hop is 2xx); label chips carry a tag icon ("Landing Page", "Marketing Site")                                                                                                                                                                                                                                                                                    |
| O1  | Overview     | "Assets Overview": primary "Start Discovery"; KPI cards Assets / Services / Technologies with info tooltips; three over-time charts; three top-10 distribution donuts (asset types, domains, technologies) with a donut/bar toggle and export                                                                                                                                                                                             |
| AG1 | Asset groups | Table: checkbox, root domain with a verified/globe icon, Source "Auto Discovery", total services, discovery duration, last updated, kebab menu; search, filter, bulk delete, paging. A group is a **discovery run per root domain**                                                                                                                                                                                                       |
| D1  | Dashboard    | Open vulnerabilities by severity; by category; Your assets (assets, services, technologies, affected services); **Asset categories** bar list from auto labels; **Security score** "100 Excellent"; API-key widget; **Newest vulnerability detections** (global feed of new checks/CVEs); **Remediation efficiency** per SLA tier with a trend; a "Vulnerability exposure" Sankey from threat-intel feeds to open/remediated              |
| S1  | Settings     | Separate shell with "← Back to app". GENERAL: My Account, API Key, **Scan IPs**. TEAM: Team, Billing, Audit Logs. SCAN CONFIGURATIONS: Template Profiles, Configurations, **Auto Retest**, **Exclusions**, **Severity Controls**. INTEGRATIONS: **Subfinder** (passive-source keys), Alerting, Ticketing, **Regressions**                                                                                                                 |
| S2  | My Account   | Header card (avatar, name, email, plan), then key/value rows: username, email, password, two-step verification, weekly digest toggle, theme segmented control (System / Light / Dark), "Delete account"                                                                                                                                                                                                                                   |
| C1  | Credentials  | "Credential Monitoring" is a top-level item                                                                                                                                                                                                                                                                                                                                                                                               |

---

## 2. OpenCTEM today

### 2.1 Navigation

- **Config:** `web/src/config/sidebar-data.ts` (`navGroups` at :98), rendered by `components/layout/app-sidebar.tsx`.
- **Size:** 7 groups and 40 leaves:
  - untitled quick links (Dashboard, My Work, Findings);
  - Scoping 5, Discovery 7, Prioritization 8, Validation 6, Mobilization 5, Insights 6.
  - Settings and Help are pinned in the footer (`sidebar-footer-links.tsx`). Settings has its own rail (`config/settings-nav.ts`, 6 groups).
- **Team switcher:** exists (`components/layout/team-switcher.tsx`, mounted at `app-sidebar.tsx:45`). The static `teams` array at `sidebar-data.ts:86-97` is leftover data.
- **Badge counts:** they exist but are off by default (`hooks/use-dynamic-badges.ts:82`, `NEXT_PUBLIC_ENABLE_SIDEBAR_BADGES`). There are only two sources, `/findings` (open findings) and `/credentials` (active leaks).
- **"+ Create":** none. The header has Search, Fullscreen, Notifications, Theme and Profile (`components/layout/header-actions.tsx:49-55`).
- **Assets:** a single row with section tabs Inventory | Groups | What changed | Suggestions (`config/section-tabs.ts:102-131`, shipped with the Scoping IA).

### 2.2 Inventory pages and rows

There are two builds of the asset list:

| Build                                                                                                  | Where                                                                                                                                     | Row today                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/assets` (all types, server-paginated)                                                                | `features/assets/components/inventory/all-assets-inventory.tsx`, `inventory-table.tsx:82-261`                                             | Name, Type, Criticality, Exposure, Internet, Owner, Risk, Findings, Last seen, Tags (2 + "+N"). **No host:port, IP, title, technologies, TLS, ASN, CNAME, favicon or screenshot**                     |
| 19 typed pages (`/assets/domains`, `websites`, `services`, `hosts`, `ip-addresses`, `certificates`, …) | `features/assets/components/asset-page.tsx` (1468 lines) + one `config.tsx` per route                                                     | Shared columns plus per-type columns. Websites: Technology, SSL, Status code. Services: Port, Protocol, Version, Technology. IPs: ASN, Type, Open ports. Certificates: Issuer, Valid until, Days left |
| `/attack-surface/external`                                                                             | `app/(dashboard)/(scoping)/attack-surface/external/page.tsx` (846 lines). A hand-rolled `<Table>`; PR #829 (open) moves it to `DataTable` | Public assets; "Technologies" shows tags                                                                                                                                                              |

**The typed pages read the wrong keys.**

- Websites reads `metadata.technology` (singular) and `metadata.server`: `assets/websites/config.tsx:13,211`.
- Services reads `metadata.technology`: `assets/services/config.tsx:60`.
- Ingest writes `technologies`, `web_server` and nested `service.{port,protocol}`.
- Certificates and IPs read flat `cert_*` and `asn`, while ingest nests them under `certificate.*` and `ip_address.*` (`api/internal/app/ingest/mappers.go:364-367,469-506`).
- Websites defaults a missing status to **200** (`websites/config.tsx:51,197,254`). That is the "no fake numbers" class; #829 fixes it.

**Shared parts already in place:**

- `DataTable`, with `rowGroups` (client and server groups, `data-table/data-table-groups.tsx`);
- `PageHeader`, `MetricStrip`, `EmptyState` and `BulkActionBar`;
- the drawer frame `DetailSheet` / `DetailHeader` / `DetailTabs` (`features/shared/components/detail-sheet-layout.tsx`) with the body parts in `detail-sheet.tsx`. It came from the sensor drawer and was adopted by findings in #812; assets already use it (`asset-detail-sheet.tsx:286`).

### 2.3 Filters, group-by, time

- **`/assets`:** a `FacetPanel` with **no per-option counts**, on purpose (`facet-filter-panel.tsx:15-16`).
  - Facets are type, criticality, BU, ownership, data classification, exposure, internet, control plane, scope, status, environment, provider, plus signals and tags (`features/assets/lib/inventory-facets.ts:101-221`).
  - The list is filtered server-side and the state lives in the URL (`inventory-url.ts`).
  - There are 6 fixed "views" presets and no saved views.
- **Typed pages:** search, a status select with counts from `/assets/stats`, `TagFilter`, and `PropertyFilter`.
  - `PropertyFilter` calls **`GET /assets/facets`** (`api/internal/infra/postgres/asset_repository.go:2177` `GetPropertyFacets`).
  - That endpoint returns top-level property keys with their top 20 values and **one count per key, not per value**.
- **API filter limits:**
  - `?properties=k:v` matches **top-level keys only** (`api/internal/infra/http/handler/common.go:260-290`), so `service.port` and `ip_address.asn` cannot be filtered.
  - `search` covers name, description and aliases, not properties (`asset_repository.go:1103-1110`).
  - Sort fields are fixed.
- **Group-by on assets:** none. Only Findings uses `rowGroups` for this (`app/(dashboard)/findings/page.tsx:93-102`).
- **Time range:** only `last_seen_after` / `last_seen_before`, used by the "not seen 30d" signal. What changed has 7/30/90 days.

### 2.4 Screenshots, technologies, TLS

- **Screenshots: none anywhere.**
  - The sensor's httpx call (`agent/internal/executor/recon.go:788-796`) passes `-silent -sc -title -server -td -ct`, with no `-screenshot`.
  - No image ships Chromium or gowitness. The `full`/`platform` stages ship semgrep, gitleaks, trivy and nuclei only (RFC-036 E2).
  - Migration `000270` removed the gowitness and wappalyzer steps from the preset pipelines.
  - `screenshot_path` appears only in `api/docs/asset-properties-schema.md:605`.
- **Technologies:** httpx `-td` emits strings such as `jQuery:3.3.1`. They are stored as `properties.technologies` (string array, GIN index) and also copied into `tags`.
  - **No category, description, icon or CPE is stored.**
  - The data exists, though: httpx's fingerprint library `projectdiscovery/wappalyzergo` (MIT, an indirect dependency of the sensor, `agent/go.mod:121`) ships `categories_data.json` and per-fingerprint `description`, `cpe`, `icon` and categories (`AppInfo` in `fingerprints.go:79-84`). A tech catalog can be built from it (§5.3).
  - The underlying Wappalyzer dataset's licence history needs checking before we vendor the JSON (owner decision D7).
- **TLS:** the sensor parser types `tls` as a bool (`agent/.../recon.go:568`). If `-tls-grab` is ever added, `json.Unmarshal` fails and the whole line is dropped silently.
  - sdk-go parses issuer, SAN and `not_after`, then drops them at `core.LiveHost` (RFC-036 E5).
  - Certificates reach the inventory only as separate `certificate` assets (CT monitor and manual entry).
  - #829 makes the certificates page read both property shapes and show "Unknown" when there is no date.
- **ASN / CNAME / favicon:** the same drop in sdk-go. CNAME exists only for domains (dnsx, `cname_target`).
- **Second sensor bug:** the http service asset ID is `http-svc-<host>` (`recon.go:578`), so two ports on one host collapse into one service.

### 2.5 Labels (tags)

- **Storage:** `assets.tags TEXT[]` (GIN). `GET /assets/tags?prefix=` lists them.
- **In rows:** shown as chips (2 + "+N").
- **Editing:** in the drawer only (`sheet-sections.tsx:277-360`).
- **Bulk:** the "Add tag" bulk dialog does **one PUT per asset** (`inventory-bulk-bar.tsx:228-240`). There is no bulk endpoint.
- **Bug:** update validation allows 20 tags (`api/internal/infra/http/handler/asset_handler.go:345,358`), while ingest allows 50 and copies every technology into `tags`. So a bulk add can fail on a tech-heavy asset.
  - Technologies should stop being copied into tags once technologies are a facet of their own.

### 2.6 Starting a scan from inventory

- **`/assets` and the typed web pages:** no scan action.
- **Repositories:** a row action and a bulk action that loop over `POST /assets/{id}/scan`, which works for repositories only.
- **`/attack-surface/external`:** "Scan Now" scans **all filtered** rows through `ScanAssetsDialog` → `POST /scans/quick` (`features/scans/components/scan-assets-dialog.tsx:69,112`).
  - `/scans/quick` takes **target strings** (1–1000), not asset IDs (`scan_handler.go:142`).
  - `POST /scans` accepts `asset_group_ids[]`.
- **Machine groups:** quick-scan creates a visible asset group per run (Scoping IA C13: 6 of 10 live groups were `quick-scan-*`).

### 2.7 Integrations

- **Overview:** `/settings/integrations` shows 6 `LinkCard` category cards (`features/integrations/config/integration-categories.ts:30-76`) above a `DataTable` of configured integrations, with a "Manage" link to each category page.
- **Category pages:** SCM, Vulnerability scanners (Tenable), Ticketing (Jira), Notification channels (+ outbox, history), SIEM (Splunk), and CI/CD (`ComingSoonPage`).
- **Configuration is always a dialog**, never a sheet. The SCM dialog has OAuth and GitHub App labelled "coming soon" (`schemas/scm-connection.schema.ts:41-48`). The notification dialog has an ad-hoc provider-then-form step.
- **Unused catalog code:** `INTEGRATION_PROVIDERS` (`features/integrations/types/integration.types.ts:357`) is never imported. `ScmConnectionsSection` and `ScmConnectionCard` are unused.
- **Providers with a working client:** GitHub, GitLab, Bitbucket, Azure DevOps, Tenable, Jira, Slack, Teams, Telegram, Email, Webhook, Splunk, and DefectDojo (API only).
  - No client for Wiz, Snyk, CrowdStrike, Linear, Asana, AWS, GCP or Azure (`api/pkg/domain/integration/entity.go:142-155`).
  - No Cloudflare provider at all.
- **Jira auth:** Basic auth with email and API token (`api/internal/infra/jira/client.go:36,110`). No OAuth and no PAT.
- **OAuth:** exists only for user login (`routes/auth.go:118-124`) and SSO. **No integration OAuth flow and no token refresh.**
- **Credentials:** `integrations.credentials_encrypted` (`migrations/000019`), AES-256-GCM with a key ring (`api/pkg/crypto/cipher.go`, `keyring.go`) and a platform-wide key.
  - Decrypt **falls back to plaintext** if decryption fails (`api/internal/app/integration/service.go:963-977`). Revisit this before storing OAuth refresh tokens.
- **Cloud connectors:** `api/internal/app/connector/connector.go` is an interface and registry only. Nothing imports it, and no provider is implemented.

### 2.8 Credential monitoring

- **Web:** `/credentials` ("Credential leaks" in Discovery) is real (1060 lines). It has `MetricStrip`, `DataTable`, group by identity, reveal (permission-gated), and resolve / accept / false-positive actions.
- **API:** CSV and JSON import plus a sensor ingest endpoint.
- **Missing:** a feed connector. HIBP and similar sources are only free-text labels. RFC-036 §6.12 lists HIBP as a per-tenant `discovery_source`.
- **Verdict:** keep it where it is. PD's top-level item matches our Discovery row, and the gap is the feed, not the UI.

### 2.9 Dashboard, overview and asset groups

- **Dashboard:** the CTEM dashboard (`web/src/features/dashboard/components/ctem-dashboard.tsx`) is action-first: the CTEM loop, KEV-bearing exposure chains (`:72`), MTTR (`mttr-card.tsx`) and Program Health (`program-health-view.tsx`). A Classic toggle remains.
  - The metric audit (2026-08, `openctemio/api#444`–`#447`) fixed an SLA that showed a fake ~100%, a threat-intel count that was global instead of per tenant, and other numbers.
  - **Today we have no:**
    - "new checks → am I affected" feed (KEV and EPSS are stored, and sensors receive new nuclei templates through content updates, but nothing joins "new" against "your technologies");
    - single security score;
    - asset-category view (auto labels do not exist yet);
    - remediation-efficiency-per-SLA-tier card.
- **Assets overview:** `/attack-surface` is the overview, and PR #857 (open) turns it into the EASM overview from `GET /easm/summary` (#839).
  - PD's "over time" charts need observation history, which is RFC-036 P4 / the inventory v2 RFC. `What changed` has 7/30/90-day state history only.
- **Asset groups:** `/assets/groups` lists **static** groups.
  - 6 of 10 live groups are quick-scan machine groups (Scoping IA C13).
  - There is no source, discovery duration or "last run". PD's groups are discovery runs per root domain; ours are containers.

### 2.10 Settings compared with PD

Our settings area is the approved Settings IA (2026-10-01, owner decisions D1–D7).

- **Config:** `web/src/config/settings-nav.ts`. It has a dedicated shell with a way back to the app and 6 groups: My account, Organization, Access, Policies, Scanning, Integrations.
- **PD's shell is the same idea.** The differences are the items below.

| PD item                           | OpenCTEM today                                                                                                                                                                                                                                                                  | Proposal (where it lives)                                                                                                                                                           |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| My Account (key/value rows)       | `/account` (Profile), `/account/security` (password + 2FA), `/account/preferences` (theme through `next-themes`, language), `/account/notifications`, `/account/activity`. **No account delete:** only `GET`/`PUT /me` exist (`api/internal/infra/http/routes/auth.go:178-179`) | Same pages. Restyle Profile as a header card + label/value rows; theme as a System/Light/Dark segmented control. "Leave or delete account" needs an API and a rule for owners (D11) |
| API Key                           | Access › API keys (`oct_` keys) and AI access (MCP)                                                                                                                                                                                                                             | No change. A key is shown once at creation, never again                                                                                                                             |
| **Scan IPs**                      | Nothing. The sensor stores the **heartbeat** client address (`api/pkg/domain/sensor/entity.go:214`). That is the address the control plane sees, not necessarily the scan egress (RFC-034 proxies)                                                                              | Scanning › **Scan egress IPs**: per zone and sensor, the egress profile and the IPs **observed** on egress (reported by the sensor through its egress path), with last seen         |
| Team, Audit Logs                  | Access › Members/Teams/Roles; Organization › Audit log                                                                                                                                                                                                                          | No change. Billing is not applicable in OSS                                                                                                                                         |
| Template Profiles, Configurations | Scanning › Scan profiles (named, `IsDefault`, per-tool config, intensity: `api/pkg/domain/scanprofile/entity.go:208-224`), Scanner templates, Template sources                                                                                                                  | Add PD's preset fields to scan profiles: per-host rate limit, custom headers, template variables, OOB/interactsh. Rename "default" to "Use for every scan" (research 06 #8)         |
| **Auto Retest**, **Regressions**  | RFC-039, continuous retest with regression reopen (PRs #866, #867, open)                                                                                                                                                                                                        | Policies › **Retest & regressions**: auto-retest per tenant (default off, per RFC-039), cadence, and "notify on regression" through a notification channel                          |
| **Exclusions**                    | Scoping › Boundaries › Exclusions (`/scope-config`). Not in Settings                                                                                                                                                                                                            | **One home: Boundaries.** Settings › Scanning gets a link row to it, not a second page. Add a "paste a list" mode (one pattern per line, `*`, CIDR)                                 |
| **Severity Controls**             | API rule overrides exist, including `SeverityOverride` (`api/pkg/domain/rule/override.go:26`, migration `000026`). **No web UI found**                                                                                                                                          | Policies › **Severity overrides**: per check/template/rule, scoped to the tenant, with a reason, audited, and shown on the finding ("severity overridden from High")                |
| **Subfinder** (passive keys)      | Nothing. RFC-036 §6.12 plans the `discovery_source` integration category                                                                                                                                                                                                        | Integrations › **Discovery sources** (a catalog category): SecurityTrails, Shodan, Censys, Chaos, Cert Spotter…, per tenant (§6.7)                                                  |
| Alerting, Ticketing               | Integrations › Notification channels, Ticketing                                                                                                                                                                                                                                 | Folded into the catalog (P3)                                                                                                                                                        |
| Weekly digest email               | Org-level scheduled digests on `/reports` (report schedules); no per-user toggle                                                                                                                                                                                                | My account › Notifications: a per-user "weekly digest" toggle over the user's own scope (data-scope aware)                                                                          |

### 2.11 Behaviour verified from PD's docs (research 06)

`research/06-projectdiscovery-ux.md` holds PD-documentation claims that each passed a 3-0 vote. That document has no evidence for PD's nav, integrations or settings; for those this document relies on the owner's screenshots.

- **The core loop to copy first:** filter → review → bulk act (label, status) → "Save filters" as a dynamic group → policy.
  - A PD dynamic group is a **stored query**, refreshed when the parent discovery reruns.
  - Ours are static (§2.5). The bulk paths take IDs only: findings `POST /findings/bulk/status` takes `finding_ids` (max 100, `api/internal/infra/http/handler/vulnerability_handler.go:608-610`), and asset labels are N PUTs.
  - **Gap:** bulk endpoints should accept a **selector**, IDs **or** the list's filter (data scope applied), so "apply to all 2,300 matches" does not page through results. Keep the BulkGuard ceiling and `operator_approved` for very large sets.
- **Triage states:** PD has 7 (open, false_positive, fixed, duplicate, fix_in_progress, accepted_risk, triaged).
  - Ours (`api/pkg/domain/vulnerability/value_objects.go:362-388`) are a superset with stricter semantics:
    - `new` / `confirmed` cover open + triaged;
    - `in_progress`;
    - `fix_applied` → `validated_fixed` → `resolved` (PD's single "fixed" collapses a claimed fix and a verified fix);
    - `false_positive` and `accepted` (approval required, with expiry);
    - `duplicate`;
    - pentest states.
  - **No change to the model.** In the UI, label the verified path clearly so "fixed" never means "someone said so".
- **Auto labels are rules, not AI:** PD's own docs call them rules-based and in early beta. Our auto-labels (the inventory v2 RFC) should be deterministic rules too, and the UI should say "rule: DNS contains `api` and response is JSON", not "AI".
- **Retest:** manual retest reverts the status when the issue is still present; auto-retest catches regressions. Both match RFC-039.
- **Template editor:** Monaco editor, run against a target, request/response debugger, lint and validate.
  - We have scanner template management (Settings › Scanning › Scanner templates; signed custom-template manifests in #869), but **no editor with run-and-debug**.
  - That is a later item. A run-against-target from the browser must go through a sensor in a zone and the scope gate, never from the API host.
- **AI features:** later, behind a tenant opt-in (§6.2).

### 2.12 Data inventory for the PD row

| Field                     | Stored                                             | In API response | Shown in web                         | Gap owner                                      |
| ------------------------- | -------------------------------------------------- | --------------- | ------------------------------------ | ---------------------------------------------- |
| Status code               | `properties.status_code`                           | yes             | generic drawer section only          | **web P0** (wrong key `http_status`)           |
| Title                     | `properties.title`                                 | yes             | generic only                         | **web P0**                                     |
| Web server                | `properties.web_server`, `service.name`            | yes             | no (reads `metadata.server`)         | **web P0**                                     |
| Technologies (+ version)  | `properties.technologies` (`Name:ver`)             | yes             | no (reads `technology`)              | **web P0**; catalog API P2                     |
| Content length, CDN, IP   | `properties.*`                                     | yes             | generic only                         | web P0                                         |
| Port / protocol           | `properties.service.*`                             | yes             | no (reads flat `port`)               | web P0; API filter on nested keys              |
| TLS issuer / SAN / expiry | `certificate` assets only; dropped from httpx      | when present    | certificates page (#829 fixes shape) | sdk-go `LiveHost` + sensor parser (RFC-036 P3) |
| ASN                       | `ip_address.asn` for IP assets; dropped from httpx | when present    | IP page (wrong shape)                | sdk-go + web                                   |
| CNAME                     | domains only                                       | for domains     | domains page                         | sdk-go + relationships (`cname_of`)            |
| Favicon mmh3              | **not stored**                                     | no              | no                                   | sdk-go + ingest                                |
| Screenshot                | **not stored**                                     | no              | no                                   | sensor + storage + API (§6.1)                  |
| Open findings count       | `assets.finding_count`                             | yes             | `/assets` Findings column            | reuse for the "Issues found" chip              |

---

## 3. Gap table

Effort: XS < 1 day, S ≈ 2–3 days, M ≈ 1 week, L ≥ 2 weeks. Value is for an operator working the external surface.

| PD pattern                                        | OpenCTEM today (file:line)                                                                                                                                  | Gap                                                                                                                                                                                                       | Effort                         | Value               |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ------------------- |
| Rich service row (I5)                             | `/assets` row has no service facts (`inventory-table.tsx:82-261`); typed pages read wrong keys (`websites/config.tsx:13,51,211`, `services/config.tsx:60`)  | Readers fixed to the ingest shape; one shared `ServiceRow` cell set                                                                                                                                       | **S** (web)                    | **Very high**       |
| Status chip by class (I5)                         | Green/other only; missing status shown as 200 (`websites/config.tsx:51`)                                                                                    | Shared `HttpStatusChip`: 2xx success, 3xx info, 401/403 warning, other 4xx/5xx destructive, unknown dashed                                                                                                | XS                             | High                |
| "Issues found" chip (I5)                          | Findings count is a column on `/assets` only                                                                                                                | Chip linking to `/findings?asset_id=` when > 0; nothing when 0                                                                                                                                            | XS                             | High                |
| IP / CNAME overflow "+N" (I5)                     | IP shown on hosts only; CNAME on domains only                                                                                                               | `OverflowChips` (first value + "+N" with tooltip). CNAME and ASN need the sdk-go fix first                                                                                                                | XS web + S sdk-go              | Medium              |
| TLS chip + issuer + SAN (I5)                      | Certificates page only, wrong shape (`certificates/config.tsx:77,119,325`); fixed by #829                                                                   | `TlsSummary` cell from the service's certificate; sdk-go must keep the httpx cert (RFC-036 #12)                                                                                                           | S web + M sdk/API              | High                |
| Labels inline + "Add label" (I5, I9)              | Drawer-only edit; bulk = N PUTs (`inventory-bulk-bar.tsx:228-240`); tag cap mismatch 20 vs 50                                                               | Inline popover add; `POST /assets/bulk/tags` (add/remove); stop copying tech into tags                                                                                                                    | S web + S API                  | High                |
| Faceted filter with value counts (I3)             | `FacetPanel` without counts by design (`facet-filter-panel.tsx:15`); `/assets/facets` = one count per key, top-level keys only (`asset_repository.go:2177`) | **Disjunctive** per-value counts; nested keys (port, ASN); value search. API shape in the inventory v2 RFC                                                                                                | M API + S web                  | Very high           |
| Group-by views (I4, I7)                           | None on assets; `rowGroups` exists (`data-table-groups.tsx`, Findings reference)                                                                            | Server groups for tech / port / domain / host / label / status / server / ASN / issuer; group header with Scan + Export; per-group paging                                                                 | M (web) + S (API group counts) | High                |
| Technologies catalog (I6)                         | Strings `Name:ver` only; no categories or descriptions                                                                                                      | Static tech catalog (name → categories, description, CPE, icon) served by the API; tech group header shows them                                                                                           | S API + S web                  | Medium–high         |
| Search follows group-by (I8)                      | Single search                                                                                                                                               | Placeholder and target (group values vs rows) follow `?group=`                                                                                                                                            | XS                             | Medium              |
| Screenshots (I1, I5)                              | None (§2.4)                                                                                                                                                 | Sensor capture in a sandbox, safe storage and serving, thumbnail cell, gallery view                                                                                                                       | **L** (sensor + API + web)     | High (triage speed) |
| Start scan from selection / group (I2, I7)        | Bulk bar has no scan; only external page scans all (`external/page.tsx:441`); `/scans/quick` takes strings                                                  | "Start scan" in the bulk bar and group header; a server dry-run returns in-scope / skipped counts; no visible machine group                                                                               | S web + S API                  | **Very high**       |
| Export (I2, I7)                                   | Typed pages export client-side CSV; `/assets` has none                                                                                                      | `useCsvExport` on `/assets` and per group; a server export when sets are large                                                                                                                            | S                              | Medium              |
| Save filter → dynamic group (I9)                  | Groups are static (`assetgroup/entity.go:14-44`)                                                                                                            | Dynamic groups (inventory v2 RFC); UI: "Save as dynamic group" next to the filter chips                                                                                                                   | M API + S web                  | High                |
| Policies (I10)                                    | None for assets                                                                                                                                             | Inventory v2 RFC; UI: Policies tab with a preview "matches N now"; actions label / notify / **archive** (no delete)                                                                                       | L                              | Medium              |
| Exclusions as pattern list (I11)                  | Boundaries › Exclusions is row-based (`/scope-config`)                                                                                                      | Optional textarea import mode (one pattern per line, `*`, CIDR) on the existing page                                                                                                                      | S                              | Medium              |
| "Ask AI" filter (I3)                              | None                                                                                                                                                        | Natural language → our filter DSL, shown as editable chips; no tenant data leaves without opt-in (§6.2)                                                                                                   | M                              | Medium              |
| Integrations catalog (G1, G3)                     | Category cards + table (`settings/integrations/page.tsx:155-173`); unused `INTEGRATION_PROVIDERS`                                                           | One catalog: Available / Connected tabs, category select, search, card grid; "Planned" for no-client providers                                                                                            | M (web)                        | High                |
| Config side panel with stepper (G2)               | Dialogs per category; 3 bespoke steppers (`scan-stepper.tsx`, `group-stepper.tsx`, `process-stepper.tsx`)                                                   | Shared `Stepper` + `IntegrationSetupSheet` on `DetailSheet`; per-provider step schema                                                                                                                     | M                              | High                |
| Jira OAuth (G2)                                   | Basic auth only (`jira/client.go:36,110`); no integration OAuth or refresh                                                                                  | Atlassian OAuth 2.0 (3LO): per-tenant client, encrypted refresh token, rotation, `cloudid` resolution                                                                                                     | M API + S web                  | Medium–high         |
| Cloud provider cards (G1)                         | Connector interface only (`app/connector/connector.go`)                                                                                                     | Shown as Planned until RFC-036 P5 implements them                                                                                                                                                         | (RFC-036 P5)                   | Very high later     |
| Short nav + badges (N1)                           | 40 leaves; badges behind a flag (`use-dynamic-badges.ts:82`)                                                                                                | Turn badges on (honest sources only); "+ Create" menu; keep the CTEM IA                                                                                                                                   | S                              | Medium              |
| Credential monitoring (C1)                        | `/credentials` real; no feeds                                                                                                                               | Feed connectors (HIBP etc., RFC-036 P5); no UI change                                                                                                                                                     | (RFC-036 P5)                   | Medium              |
| Lens groups collapsed; mode name in control (I12) | n/a (no asset groups)                                                                                                                                       | IP, CNAME, status, title, web server, ASN and issuer groups start collapsed; our select already shows the active mode                                                                                     | XS (with P2)                   | Medium              |
| CNAME group as a takeover lens (I12+)             | Dangling-DNS checks with takeover fingerprints (#852, open)                                                                                                 | **Better than PD:** a CNAME group whose provider is in the fingerprint list gets a "Takeover-prone provider" warning chip linking to the dangling-DNS exposures                                           | S                              | High                |
| Redirect chain in status (I13)                    | Only the final status is stored                                                                                                                             | Keep httpx `chain_status_codes`, then render "301, 200 OK" with the chain in a tooltip                                                                                                                    | XS web + S sdk-go              | Low–medium          |
| Bulk act by filter (research 06 #2, #7)           | Bulk = IDs only (findings max 100; assets N PUTs)                                                                                                           | Selector = IDs **or** filter, data scope applied, BulkGuard ceiling kept                                                                                                                                  | M (API)                        | High                |
| "Start Discovery" CTA, groups as runs (O1, AG1)   | Discovery is a scan type; groups are static containers polluted by quick-scan                                                                               | Attack surface overview gets "Start discovery" (seeds → RFC-036 pipeline). Groups list gets a Source column (Manual / Dynamic / Discovery) with last run and duration, and machine groups disappear (C13) | S web + S API                  | Medium–high         |
| Over-time charts (O1)                             | State history only                                                                                                                                          | Needs observation history (RFC-036 P4 / inventory v2 RFC); until then, no chart rather than a flat line                                                                                                   | (blocked)                      | Medium              |
| "Newest detections → am I affected" (D1)          | KEV/EPSS stored; template content reaches sensors; no join to tenant technologies                                                                           | Dashboard card: new checks in 7/30 days × your services' technologies and versions → "could apply to N services", one-click check (or auto, template-triggered scans)                                     | M                              | **Very high**       |
| Security score (D1)                               | None (risk scores per asset/finding)                                                                                                                        | Only with a visible formula and a "Not enough data" state. PD shows **100 "Excellent" with 0 scanned services**, the anti-pattern our metric audit removed                                                | S–M                            | Medium              |
| Asset categories from auto labels (D1)            | None                                                                                                                                                        | Bar list of rule-based auto-label counts (inventory v2 RFC), each bar a filtered inventory link                                                                                                           | S (after labels)               | Medium              |
| Remediation efficiency per SLA tier (D1)          | MTTR card; SLA policies; SLA metric fixed in the 2026-08 audit                                                                                              | Per-tier "within SLA" share and count of remediated in 30 days, from the same SLA source as the findings page                                                                                             | S                              | Medium              |
| Scan egress IPs (S1)                              | Heartbeat address only (`sensor/entity.go:214`)                                                                                                             | Scanning › Scan egress IPs from observed egress per zone/sensor                                                                                                                                           | S–M                            | Medium–high         |
| Passive-source keys (S1)                          | None (RFC-036 §6.12 planned)                                                                                                                                | Integrations › Discovery sources                                                                                                                                                                          | M (RFC-036 P5)                 | Medium–high         |
| Severity controls (S1)                            | API rule overrides, no UI                                                                                                                                   | Policies › Severity overrides                                                                                                                                                                             | S web                          | Medium              |
| Auto retest + regressions settings (S1)           | RFC-039 in flight (#866/#867)                                                                                                                               | Policies › Retest & regressions                                                                                                                                                                           | S web                          | High                |
| Weekly digest, account delete, theme control (S2) | Org digests only; no delete API; theme in Preferences                                                                                                       | Per-user digest toggle; leave/delete flow (D11); segmented theme control                                                                                                                                  | S                              | Low–medium          |
| Scan config presets (research 06 #8)              | Scan profiles with `IsDefault`, per-tool config                                                                                                             | Add per-host rate limit, headers, template variables, OOB settings; "Use for every scan" label                                                                                                            | S–M                            | Medium              |
| Template editor (research 06 #9)                  | Template management only                                                                                                                                    | Later: editor + run against an in-scope target through a sensor + debugger + lint                                                                                                                         | L                              | Medium              |

---

## 4. Design decisions that keep PD's look inside our contract

1. **A row is a table row, not a card.**
   - PD's card list loses column sort, keyboard row selection, the bulk bar and the drawer.
   - We keep **one `DataTable`** with rich cells:
     - **Service:** favicon, `host:port` in mono, then chips for status, issues, IP, ASN and CNAME, then a second chip line for labels.
     - **Screenshot:** thumbnail with the title truncated under it.
     - **Technologies.**
     - **TLS certificate:** chip, issuer and SAN.
     - **Last seen.**
     - **Actions.**
   - Below `md`, the same data renders as the table's phone row card, as the contract already requires.
2. **Group-by is the toolbar select, not chips** (contract §3, "Group by is a toolbar select … not tabs").
   - PD's chips are a different control for the same thing. If the owner prefers chips, it is a **contract amendment for every grouped list** (Findings, Sensors, Assets), not an Assets exception (D2).
3. **Filters keep the one icon-only `FilterButton`.**
   - PD's "Add Filters" menu maps onto the contract's sanctioned **popover** form: `FilterButton` inside `PopoverTrigger`.
   - The popover has a field list on the left and values with counts, search and "Apply (n)" on the right.
   - Active filters show as removable chips under the toolbar.
   - For ≥ 3 dimensions the contract asks for the side `FacetFilterPanel`. `/assets` already has one, so the popover is a **second entry point onto the same URL state**, not a second filter system. D3 picks one.
4. **Counts only when they are true.** A value count is shown only when it comes from the disjunctive facet query (§5.2). A zero is shown uncoloured. A value list is capped (top 50) with "search all values".
5. **No defaults for missing facts.** "Status unknown", "Not collected" (no TLS probe ran) and "No TLS" (probe ran, plain HTTP) are three different states, and none of them is shown as healthy. This continues #829.
6. **Screenshots are a view, not a tab.**
   - PD has a Screenshots tab. We put a `ViewSwitcher` (list | gallery) on Inventory instead, so filters and selection carry over.
   - The Assets tabs stay Inventory | Groups | What changed | Suggestions, plus **Policies** when that feature ships (inventory v2 RFC).
   - PD's "Domains" tab is our `/assets/domains`, reachable as a type filter.

---

## 5. Proposed UI plan, phased

Each phase ships alone and changes no URL.

### P0: Show the data we already have (web only, ~1 week)

1. **Fix the readers on the typed pages** (`websites`, `services`, `ip-addresses`, `certificates` configs):
   - `technologies`, `web_server`, `status_code`, `title`, nested `service.*`, `ip_address.*` and `certificate.*`;
   - one helper, `features/assets/lib/service-facts.ts`, next to #829's `certificate-facts.ts`, with tests over both legacy and ingest shapes;
   - no value is defaulted.
2. **Extract shared cells** into `features/assets/components/service-cells/`:
   - `HttpStatusChip`, `OverflowChips`, `TechChips` (parses `Name:ver` into name + version; "No technologies" chip), `TlsSummary` (driven by `certificate-facts`), `IssuesChip`, `LabelChips` (inline "+ Add label" popover, gated on `assets:write`) and `ServiceIdentity` (favicon slot + mono `host:port`).
   - Use them on `/assets` (for `service` rows), `/assets/websites`, `/assets/services` and `/attack-surface/external`. **Sync rule:** no page keeps its own copy.
3. **"Start scan" in the `/assets` bulk bar.**
   - Reuse `ScanAssetsDialog`, which `/attack-surface/external` already uses, so there is one scan entry point.
   - Hidden without `scans:write`.

### P1: Service row, honest facets, bulk labels (~2 weeks; API shape from the inventory v2 RFC)

1. **`ServiceRow` column set:** one exported `serviceColumns` for `DataTable`, used by Inventory whenever the type filter is `service` (the default inventory view for an EASM tenant, D4).
2. **Facets API (UI requirements):**
   - `GET /assets/facets?field=port&…same filters as /assets…` returns `[{value, count}]` for one field.
   - Counts are computed **with every active filter except the field's own** (disjunctive faceting).
   - Supported fields: port, status, title (prefix search), web server, technology (per element), domain, host, IP, ASN, CNAME, issuer, TLS state, label, has-screenshot, has-favicon, has-technology.
   - Values are sorted by count, at most 50 per call, with a `q` for value search.
   - The tenant is always taken from the token and data scope is applied, so restricted members see only their in-scope counts.
3. **Filter popover:**
   - a shared `FacetPopover` in `features/shared` (field list, value list, counts, search, "Apply (n)");
   - `FilterButton` stays the trigger;
   - active chips come from the same URL state as `FacetPanel`.
4. **Bulk labels:** `POST /assets/bulk/tags {asset_ids|filter, add[], remove[]}`, one request, audited. The cap is unified (D5), and technologies stop being copied into tags.
5. **"Save as dynamic group"** next to the filter chips, once dynamic groups exist (inventory v2 RFC).

### P2: Group-by views and group scan (~2 weeks)

1. **Groups on `/assets?group=`:**
   - dimensions: technology, port, root domain, host, label, status code, web server, ASN, certificate issuer, IP, CNAME, title;
   - IP, CNAME, status, title, web server, ASN and issuer groups **start collapsed**: they are lenses for spotting clusters (shared hosting, a load balancer fronting 26 services, every "403 Forbidden");
   - a CNAME group whose provider is in the dangling-DNS takeover fingerprint list (#852) gets a "Takeover-prone provider" warning chip linking to its dangling-DNS exposures;
   - server groups, paginating the **groups** (`groups`, `expandedKeys`, `useLazyGroupRows`), exactly as the contract's large-group rules say;
   - the first group open, its first 5 rows, then "Showing 5 of 22 · Show 20 more" (PD's prev/next maps onto this footer).
2. **Group header:**
   - name (mono for ports, hosts, domains and technologies), a "N services" count, then **Scan** (outline, `h-7`) and **Export** (icon) as the two allowed group actions, then the collapse chevron.
   - Both actions are hidden without permission.
3. **Technology groups:**
   - The header adds the first category chip, "+N more" and the one-line description, from a **tech catalog** endpoint (`GET /technologies/catalog?names=…`, served from vendored fingerprint metadata; licence per D7).
   - The version stays on the service row (`jQuery 3.3.1`).
   - The CPE in the catalog is a later input for matching vulnerable versions, which is out of scope here.
4. **Search follows group-by:** with `?group=port` the search box searches group values ("Search ports…"); without grouping it searches rows.
5. **Group scan:** see §6.4. The dialog shows the server's dry-run before anything starts.

### P3: Integrations catalog (~2–3 weeks)

1. **Route:** `/settings/integrations` becomes the catalog. The category pages stay as deep links for their extra screens (Jira routing rules, notification outbox and history), reached from the provider's Connected row.
2. **Layout:**
   - `PageHeader` "Integrations";
   - tabs **Available | Connected** (`?tab=`);
   - search and a category select;
   - a card grid grouped by category with section headings;
   - cards show a logo tile, name, category chip and one line, plus "Connected" when at least one connection exists.
3. **The source of truth** is one provider registry built from `INTEGRATION_PROVIDERS`, which today is dead code. Each entry has category, auth methods, permission, module, `hasClient` (mirrors `HasClient` in `entity.go:142-155`) and a step schema.
   - **Providers without a client render as "Planned"** (dashed, no button), never as a form that saves something nothing reads (the silently-inert class).
   - A test asserts the web registry and the API's `HasClient` agree.
4. **Setup panel:**
   - `IntegrationSetupSheet` = `DetailSheet` (width `xl`) + a **shared `Stepper`** (new `features/shared/components/stepper.tsx`).
   - The steps are **Name → Authenticate → Defaults → Test**.
   - Then migrate `scan-stepper.tsx` and `group-stepper.tsx` to the shared `Stepper` and delete the copies.
   - The auth method is two option cards when a provider has more than one method.
   - Secrets use `OneTimeSecretField` and are never echoed back.
5. **Connected tab:**
   - a `DataTable` with name, category, status (`StatusBadge` with the last delivery or sync error), last sync and modified;
   - Edit opens the same sheet at the "Defaults" step;
   - Disable and Delete go in the `⋯` menu with `ConfirmDialog destructive`.
6. **Contract note:** this is the first sheet used for a **create/edit form** (the contract says dialogs for forms, sheets for quick detail). The stepper-in-a-sheet needs a contract line (D6). The argument for it is that setup is long, has an external redirect (OAuth), and benefits from keeping the catalog visible.

### P4: Jira OAuth (~1–2 weeks, API-heavy)

- **Flow:** Atlassian OAuth 2.0 (3LO).
  - `GET /integrations/oauth/jira/start` returns an authorize URL with `state` (signed, bound to tenant, user and integration draft, short TTL) and PKCE.
  - The callback exchanges the code and resolves `cloudid` via accessible-resources. The user picks the site if there are several.
- **Scopes:** `read:jira-work write:jira-work offline_access` (plus `manage:jira-webhook` if bidirectional sync uses dynamic webhooks).
- **Storage and refresh:** see §6.3.
- **UI:** "OAuth 2.0 (recommended)" and "API token" option cards.
  - The token path stays for Jira Data Center (PAT) and for tenants that cannot register an Atlassian app.
  - Self-hosted deployments need the operator to register an Atlassian OAuth app (D8).

### P5: Screenshots (~3–4 weeks across sensor, API and web; RFC-036 P3 "optional gowitness")

- **Sensor:** see §6.1.
- **API:**
  - `asset_screenshots(tenant_id, asset_id, sha256, captured_at, width, height, bytes, storage_key)`;
  - retention **30 days** (RFC-036 O7);
  - `GET /assets/{id}/screenshot` streams the latest, after tenant and data-scope checks.
- **Web:**
  - a thumbnail cell (lazy, `loading="lazy"`, fixed box, placeholder icon when none);
  - a gallery view (`ViewSwitcher` list | gallery, `?view=gallery`) over the same filtered query;
  - a larger image in the asset drawer;
  - a "Has screenshot" facet.

### P6: Nav (~2–3 days)

- **Badges on**, with only these sources (each from an existing count endpoint, hidden when the call fails, never a cached guess):
  - Findings: open;
  - Exposures: open;
  - Credential leaks: active;
  - Scans: running;
  - Suggestions: pending (on the Assets tab).
- **"+ Create" menu under the team switcher:**
  - New scan, Add assets, Add target to boundaries, Connect integration, Start a cycle.
  - Each item is permission-gated, and the menu is hidden when empty.
- **No other nav changes.** PD's 10 items are a single-stage product. Our 6 CTEM groups are the approved IA, and the Scoping IA already cut 45 leaves to 41.
- **Optional:** a "compact" sidebar preference that collapses groups to their headers, if the owner wants PD's feel (D1).

### P7: Dashboard additions (~2 weeks)

What is worth taking from PD's dashboard, in order:

1. **(a) "New checks: am I affected?"**
   - **The data:** checks (nuclei templates via content updates, KEV entries) added in the last 7/30 days.
   - **The join:** the technologies and versions **we have seen** on in-scope services.
   - **The card shows:** new checks, "could apply to N services", "checked so far".
   - **Per row:** a one-click check, or automatic through template-triggered scans (R2).
   - **Honesty:** a service with no technology data counts as "unknown", never as "not affected".
   - This is PD's "Newest vulnerability detections" turned from a global news feed into a tenant question.
2. **(b) A transparent security score, or none.**
   - The formula is in a tooltip, and it is computed from open exposure over in-scope services that were actually scanned in the last 30 days.
   - With nothing scanned it says **"Not enough data"**, never 100. PD shows "100 Excellent" with 0 scanned services. That is the fake-number pattern the 2026-08 metric audit removed (the SLA showed ~100% from a dead enum literal).
   - Gate it on D12.
3. **(c) Asset categories:** counts of rule-based auto labels (Authentication, Internal tool, Marketing site, Errors page, Online store…). Each bar opens the filtered inventory.
4. **(d) Remediation efficiency per SLA tier:** "within SLA" per severity and the number remediated in 30 days.
   - It uses the same SLA source as the findings list and is re-verified against the metric-audit fixes.
   - It is hidden when no SLA policy exists.
5. **(e) Trends over time:** only after observation history exists (RFC-036 P4). No flat placeholder lines.
6. **(f) "Start discovery"** is the primary action on the Attack surface overview (#857), not on the dashboard. Asset groups get Source / Last run / Duration columns (§3).
7. **(g) A developer onboarding card:** "Create an API key" links to Access › API keys. The `oct_` key is shown once at creation; the card never displays an existing key.

**Not taken:** the global "14,028 trending exploits" Sankey. A platform-wide number on a tenant dashboard is the "threat-intel global, not tenant" defect the metric audit fixed.

### P8: Settings additions (~1–2 weeks, mostly web)

These follow the Settings IA groups. There is no new top-level group.

- **My account › Profile:**
  - a header card + label/value rows (name, email, password, two-step verification state, weekly digest toggle, theme segmented control);
  - "Leave or delete account" (D11).
- **Policies:**
  - **Severity overrides** (UI over the existing rule-override API);
  - **Retest & regressions** (RFC-039).
- **Scanning:**
  - **Scan egress IPs**;
  - a link row "Exclusions (in Scoping › Boundaries)";
  - the scan-profile preset fields.
- **Integrations:** a **Discovery sources** category in the catalog.

---

## 6. Security notes

### 6.1 Screenshots of attacker-controlled pages

- **Capture runs on the sensor only**, as a scan step on assets the scan already resolved through the ownership gate and exclusions. Never in the API process, never in the browser.
- **Sandbox:**
  - Headless Chromium in its **own container** (a separate image or stage, not `platform`):
    - non-root;
    - read-only root filesystem;
    - `--no-sandbox` **not** used (rely on user namespaces or the seccomp profile);
    - `--disable-extensions`, `--disable-gpu`;
    - no persistent profile (a fresh profile dir per job in a tmpfs).
  - Downloads, notifications and permissions denied.
  - JavaScript on by default, because pages need it to render; a per-scan-profile switch can turn it off.
- **Network:**
  - The browser's egress goes through the **RFC-034 egress profile** with a policy that allows only the target's resolved scope.
  - It denies RFC 1918, link-local (incl. `169.254.169.254` and other metadata IPs), loopback and the sensor's own control-plane endpoints, **including after redirects and for subresources**.
  - A page on an in-scope host must not be able to make the browser fetch an internal URL. The sensor-side scope check (RFC-023 D7/D8) applies to every request the browser makes, not just the first.
- **Budget:** a hard timeout per page (e.g. 15 s), a fixed viewport, max one page per target, and per-host politeness from RFC-030.
- **Output:**
  - **PNG or WebP only.** The image is re-encoded on the sensor and validated again on the API (decode, check magic bytes and dimensions, re-encode).
  - **No SVG**, no HTML snapshot, no PDF.
  - Size caps: e.g. ≤ 1 MB per image, max 1920×1080, plus a thumbnail.
  - EXIF and metadata are stripped.
- **Storage:** keyed by tenant and asset, not guessable. Never written to a public bucket. Retention is 30 days.
- **Serving:**
  - Through the API with tenant and data-scope authorization only, and no direct object-store URLs to the browser (or short-lived signed URLs bound to the tenant if ever needed).
  - Headers: `Content-Type: image/png` (or `image/webp`) set by the server, never taken from the upload; `X-Content-Type-Options: nosniff`; `Content-Disposition: inline`; `Content-Security-Policy: default-src 'none'`; `Cache-Control: private`.
  - The web renders it as `<img>` only. It is never shown in an iframe and never as `dangerouslySetInnerHTML`.
- **The page title is untrusted text.** It is rendered as text and length-capped, and CR/LF are stripped before logging (`strings.ReplaceAll`, per the CodeQL note in RFC-036 §6.13).

### 6.2 "Ask AI" / natural-language filters

- **Default: no external LLM.**
  - The feature translates a sentence into **our filter DSL** (the same URL state as the chips).
  - The result is shown as editable chips **before** it applies. The user sees exactly what will run.
- **What may leave the platform:** only the sentence the user typed and the **schema** (field names and allowed operators). No asset values, hostnames, findings or counts.
- **Sending even that** to an external model requires an explicit **tenant opt-in** (organization setting, owner or admin, audited), with a provider the tenant configures. Otherwise the feature uses a local or self-hosted model or a rule-based parser, or is hidden.
- **The model never queries data.** It only produces a DSL string, which the API parses with the normal validator (allowed fields, operators, value limits), under the user's own permissions and data scope. Prompt injection from asset content cannot reach it, because asset content is never in the prompt.

### 6.3 OAuth tokens for integrations

- **Per tenant.** Tokens belong to an integration row of one tenant, resolved by `tenant_id` from the authenticated context, never from the callback's parameters. `state` binds tenant, user, integration draft and a nonce; it is single-use and expires in 10 minutes. PKCE (S256).
- **Encrypted at rest:** access and refresh tokens use the integration store's AES-GCM key ring.
  - **Remove the plaintext fallback** on decrypt failure (`service.go:963-977`) for OAuth rows at least: a failed decrypt is an error, not a token.
- **Refresh:**
  - Refresh shortly before expiry, under a per-integration lock (Redis or a DB row claim) so concurrent workers do not race.
  - Store the **rotated** refresh token atomically. Atlassian rotates refresh tokens, and losing the new one locks the integration out.
- **Failure handling:** `invalid_grant` marks the integration `needs_reauth`. The Connected row shows it with a "Reconnect" button, and the outbox stops retrying.
- **Revocation:** Delete revokes at the provider where an endpoint exists, then deletes locally. Audit log entries for connect, refresh failure, reauth and delete.
- **Least privilege:** request only the scopes the features use, and show them on the consent step.

### 6.4 "Scan" on a selection or a group

- **The client sends a selector, not a target list:** asset IDs for a selection, or the group key and filter for a group.
- **The API resolves it at dispatch time**, through:
  - the ownership/attribution gate (RFC-036 P0: unconfirmed names are skipped);
  - scope exclusions;
  - module and permission checks;
  - the RFC-030 rate and fan-out caps.
- **Dry-run first.** The dialog shows the result before anything starts: "Scan 268 services: 241 confirmed in scope, 27 skipped (needs review or excluded)", with the reasons broken down.
  - The final run resolves again, because the set may change between dry-run and start.
- **No visible machine group per run** (Scoping IA C13). The run records its selector and resolved targets.

### 6.5 Policies

- **Actions are add/remove label, notify and archive. No hard delete from automation.** An archived asset is recoverable and keeps its history.
- A policy shows a live "matches N assets now" from the same query as the inventory before it is saved.
- "Existing + future" asks for confirmation with that number.

### 6.6 Scan egress IPs

- **List only the viewing tenant's own sensors and zones.** Never another tenant's sensor IPs, and never a shared pool's per-tenant assignments.
- **Shared platform sensors** (RFC-036 O2, P6, hosted only) are shown as the **published range document**, the same for every tenant, not as live per-sensor addresses.
- **Show observed egress, not the heartbeat source.** With an RFC-034 egress profile the two differ, and listing the control-plane address would tell a customer to allowlist the wrong IP.
- **Visibility:** the page needs `sensors:read` (admin-only per the 2026-10 authz decisions). The values are treated as infrastructure facts: not in exports, not in MCP output by default.

### 6.7 Passive-source API keys

- **Per tenant:**
  - stored in the encrypted integration store;
  - resolved with `ListByProvider(ctx, tenantID, provider)`;
  - never shared across tenants (RFC-036 O1);
  - never shown after saving (write-only field with a "replace" action);
  - "Test" calls the provider from the server and returns only ok/quota/error.
- **Delivery to sensors:**
  - by reference or sealed to the sensor's key (RFC-040 Q8);
  - never in plain job payloads or logs;
  - scoped to the job, and dropped after it.
- **Quotas:** exhaustion degrades to "skipped, quota" on the run. It never retries through another tenant's key.

### 6.8 Scores and counts

- **A score with no input is "not enough data", not a perfect value.**
- Every headline number on the dashboard cites its source in a tooltip (formula and window) and respects data scope.
- Global numbers (threat-intel totals) are never shown as if they were the tenant's.

---

## 7. Top recommendations, ranked by value / effort

| Rank | Recommendation                                                                                                                                                 | Value     | Effort | Phase |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------ | ----- |
| 1    | Fix the typed pages' readers so stored httpx data shows (technologies, server, status, title, port), with no defaults                                          | Very high | S      | P0    |
| 2    | Shared service cells (`HttpStatusChip` with redirect chain, `TechChips`, `TlsSummary`, `IssuesChip`, `OverflowChips`, `LabelChips`) on every asset list        | High      | S      | P0    |
| 3    | "Start scan" from a selection or group, with a server dry-run (in scope / skipped and why) and no machine groups                                               | Very high | S–M    | P0/P2 |
| 4    | The core loop: disjunctive facet counts + filter popover → bulk act **by selector** (IDs or filter) → "Save as dynamic group"                                  | Very high | M      | P1    |
| 5    | Dashboard "New checks: am I affected?" (new templates and KEV × your technologies and versions, one-click check)                                               | Very high | M      | P7    |
| 6    | Group-by on assets (tech with catalog, port, domain, host, label; collapsed lenses for IP / CNAME / status / title / server) with the CNAME takeover flag      | High      | M      | P2    |
| 7    | Integrations catalog (Available / Connected, categories incl. Discovery sources, "Planned" for no-client providers) with a shared `Stepper` in a `DetailSheet` | High      | M      | P3    |
| 8    | Settings: Retest & regressions (RFC-039), Severity overrides (existing API), Scan egress IPs                                                                   | High      | S      | P8    |

**Next after these:**

- bulk label API and the tag-cap fix (P1);
- keeping httpx cert/ASN/CNAME/favicon in sdk-go and the sensor, including the `tls` bool bug (RFC-036 P3), then screenshots in a sandbox (P5);
- Jira OAuth (P4);
- an honest security score (D12);
- asset categories and remediation efficiency (P7);
- nav badges and "+ Create" (P6);
- scan-profile preset fields;
- a template editor;
- the policies and "Ask AI" UI once the inventory v2 RFC lands.

---

## 8. Owner decisions

**D1–D13 were approved as recommended on 2026-10-03.** D14–D16 are still open.

| #   | Decision                                  | Options                                                        | Recommendation                                                                                                                |
| --- | ----------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| D1  | Nav: copy PD's flat ~10-item nav?         | flat / keep CTEM IA + badges + "+ Create" / add a compact mode | **Keep the CTEM IA**, turn badges on, add "+ Create". Optional compact mode later                                             |
| D2  | Group-by control                          | toolbar select (contract) / PD-style chips everywhere          | **Select.** If chips are wanted, amend the contract for all grouped lists at once                                             |
| D3  | Filter entry on Assets                    | side `FacetPanel` / PD popover / both on one URL state         | **Popover as the default** (it fits value counts and search better), the panel removed, so there is one system                |
| D4  | Inventory default view for EASM tenants   | all assets / web services first                                | **Web services first** when the `attack_surface` module is on; one click to all                                               |
| D5  | Tag cap                                   | 20 / 50                                                        | **50** everywhere, after technologies stop being copied into tags                                                             |
| D6  | Forms in a side sheet (integration setup) | dialog (contract) / sheet + stepper                            | **Sheet + stepper** for multi-step setup with external redirects; amend contract §8                                           |
| D7  | Technology catalog data source            | vendor wappalyzergo's JSON / maintain our own / names only     | **Vendor wappalyzergo's data after a licence check** of the upstream fingerprint dataset; names-only fallback                 |
| D8  | Jira OAuth for self-hosted                | operator-registered Atlassian app / hosted only                | **Operator-registered app**, configured in the admin console; token method stays                                              |
| D9  | "Ask AI" filters                          | off / local parser only / external LLM with tenant opt-in      | **Local DSL parser first**; external model only with tenant opt-in, schema-only prompts                                       |
| D11 | "Delete account"                          | none / leave organization / delete user                        | **Leave organization** for members; owners transfer first; user deletion stays an admin-console action (audit trail kept)     |
| D12 | Security score                            | none / transparent score with a "not enough data" state        | **Transparent score only**, with the formula in a tooltip and no score without recent scans; otherwise leave it out           |
| D13 | Bulk actions by filter                    | IDs only / IDs or filter selector                              | **Selector** (IDs or filter), data-scoped, with the BulkGuard ceiling and operator approval above it                          |
| D10 | Screenshots                               | build now / after RFC-036 P3 pipeline                          | **After RFC-036 P0–P3**: they need the recon tools shipped and the egress profile; ship the UI cells with the placeholder now |
| D14 | Table density default                     | one density / compact default + comfortable                    | **Compact default** for single-line lists; comfortable for multi-line service rows; per-user preference                       |
| D15 | Saved views vs dynamic groups             | one concept / two                                              | **Two:** a view is a personal or team lens; a group is a scan and policy target                                               |
| D16 | Virtualized "Scroll all" on 100k lists    | no / yes with keyset paging                                    | **Yes, after keyset pagination** in the API; page size stays the default                                                      |

---

## 9. Mock

The HTML mock is not committed. It was built in the analysis session and attached to the PR description. It uses the real tokens from `web/src/styles/theme.css` (light and dark), the system font stack the app uses, and example.com data. It shows:

- **Inventory:**
  - service rows;
  - status chips by class, "issues found", "+N" IP and CNAME overflow, inline labels, screenshot thumbnail with the title under it, "No technologies", TLS states (valid, expiring, expired, no TLS, not collected);
  - the filter popover with counts;
  - group-by select with technology groups (categories, description) and label, port, domain and host groups (N services, Scan, Export, collapse, per-group paging);
  - a search placeholder that follows the grouping;
  - "Save as dynamic group";
  - the bulk bar (Start scan, Label, Add to group, Export);
  - the group-scan confirmation with in-scope / skipped counts;
  - a gallery view;
  - a Policies tab with one policy card and a "matches N now" preview.
- **Group lenses:** IP, CNAME, title and status groups start collapsed, and a CNAME group on a takeover-prone provider carries a warning chip. Status chips show the redirect chain ("301, 302, 200 OK").
- **Integrations:**
  - catalog by category with Connected and Planned states;
  - Connected tab;
  - the Jira setup sheet with a 3-step stepper and OAuth / API token option cards.
- **Dashboard variant:**
  - "New checks: am I affected?";
  - a security score in its honest "Not enough data" state with the formula tooltip;
  - asset categories.
- **Settings shell** (Settings IA groups):
  - the Profile page as label/value rows (2FA state, weekly digest, theme segmented control, leave/delete);
  - the proposed new items (Severity overrides, Retest & regressions, Exclusions link, Scan egress IPs, Discovery sources);
  - a Scan egress IPs table.

## 10. Design-system changes

Source: `research/07-modern-ui-ux.md`, which has 11 findings from vendor docs that each passed a 3-0 vote (finding 11 passed 2-1).

- Most rest on one vendor's own documentation. They show what that vendor does, not that it works better.
- Where a point below is our own inference, it says so.

Each point maps to what `docs/ui-style-contract.md` (the "contract") and our components do today, with a verdict of **adopt**, **already have** or **reject**. The proposed contract edits follow as a diff-style list.

These are proposals. The contract is not changed in this PR, because points 2, 4 and 6 change behaviour on every list page and need the owner's sign-off (D14–D16).

### 10.1 Mapping

| #   | Pattern (source)                                                                                                                                                  | Today                                                                                                                                                                                                                                                                                                                                              | Verdict                                                                                   | Why                                                                                                                                                                                                                                                                                                   |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | One unified, resizable, collapsible sidebar, the same links at every scope; tabs only inside a module (Vercel, Tenable)                                           | Collapsible (`collapsible`, `SidebarRail` in `web/src/components/layout/app-sidebar.tsx:39,91`), not resizable. Tabs only inside a module through `SectionTabs` (contract §1.3). Settings **swaps** the sidebar content (Settings IA), and the admin console has its own shell (`app/(admin-console)/admin/(console)/layout.tsx`)                  | **Already have**, plus a small **adopt** (resizable width)                                | Same links at every _tenant_ scope already holds. Settings swapping the rail and a separate admin shell are deliberate: different audiences and permissions (RFC-022, Settings IA). Making the width resizable (persisted per user) is cheap                                                          |
| 2   | Row virtualization (TanStack Virtual) inside the shadcn table, with cursor-paginated server fetching for 100k+ rows                                               | `DataTable` (`features/shared/components/data-table/data-table.tsx:91-110`) uses page/offset server pagination (`manualPagination`, `pageIndex`); `@tanstack/react-virtual` is not a dependency (`web/package.json:70` has only react-table)                                                                                                       | **Adopt, scoped**                                                                         | Pages of 25–100 rows do not need virtualization. Use it only for an "all rows" scroll mode on assets and findings, together with **keyset (cursor) pagination** in the API, because offset paging degrades at 100k and shifts rows under concurrent ingest. The page-size UI stays the default        |
| 3   | Server facets per query: dimensions top-N with counts, measures as range sliders (Datadog)                                                                        | `FacetPanel` has no counts by design (`facet-filter-panel.tsx:15-16`). `/assets/facets` gives one count per key. Risk score has min/max query params (`min_risk_score`, `max_risk_score`), but no slider                                                                                                                                           | **Adopt**                                                                                 | With the condition from §4.4: counts are **disjunctive** (all other active filters applied), or they mislead. Measures: risk score, CVSS, EPSS, age, open-port count as range sliders with the histogram's min/max from the same query                                                                |
| 4   | Discrete density, compact 32px default for assets and findings plus comfortable (Carbon, Primer); one column sorted by default                                    | One density: header `h-10`, cells `p-2` (`web/src/components/ui/table.tsx`). Default sort is per page, not a rule                                                                                                                                                                                                                                  | **Adopt**                                                                                 | Rich service rows (§4.1) are multi-line, so they use comfortable. Single-line lists (findings, scans, sensors) default to compact. A per-user preference, not URL state. "Always a default sort" closes the "dead sort arrows" class found in the 2026-09 consistency campaign                        |
| 5   | Batch action bar on selection: row menus disabled while it shows, explicit deselect (Carbon)                                                                      | `BulkActionBar` floats at the bottom with a count, Clear and Escape (`features/shared/components/bulk-action-bar.tsx`). Row `⋯` menus stay active                                                                                                                                                                                                  | **Already have** (bar, deselect) + **adopt** (disable row menus)                          | The floating bottom bar is a deliberate choice (selecting must not shift the list), so we keep it rather than Carbon's top bar. Disabling row menus in batch mode prevents acting on one row while believing the action applies to the selection                                                      |
| 6   | Saved views as non-destructive lenses (filter, sort, grouping, columns), separate from the data (Linear)                                                          | State in the URL (contract §3); 6 fixed preset "views" on `/assets` (`inventory-facets.ts:249-280`); saved views deferred (`inventory-url.ts:10-11`)                                                                                                                                                                                               | **Adopt**                                                                                 | A `saved_views` entity: name, page, URL query, columns, density; personal or shared with the team; it never changes data. **Distinct from dynamic groups**: a group is a scan/policy target, a view is only a lens. The UI must not blur the two (D15)                                                |
| 7   | Triage as a first-class inbox step (Linear)                                                                                                                       | `new` → `confirmed` exists (`api/pkg/domain/vulnerability/value_objects.go:362-363`); My Work (`sidebar-data.ts:112`) and the Findings verification queue are the closest. No "inbox" view of unreviewed `new` findings per owner                                                                                                                  | **Adopt**                                                                                 | A Findings section tab **Inbox** = `status=new`, scoped to my teams and assets, with keyboard triage (confirm, false positive, duplicate, assign). No new state: `new` already means "not triaged". Our inference: re-detected, newly-KEV and newly-exposed findings re-enter it                      |
| 8   | Duplicate grouping by fingerprint with unmerge; mutually exclusive states; conditional snooze (Sentry)                                                            | Findings carry a `fingerprint` and `occurrence_count` (`api/pkg/domain/vulnerability/finding.go:171,281`); a `duplicate` status; group by CVE/asset. One status per finding already. Cross-scanner dedup is a known gap (VM audit 2026-08). Snooze exists only for asset staleness (`features/assets/types/asset.types.ts:1069`). No merge/unmerge | **Adopt** (merge/unmerge, conditional snooze); **already have** (exclusive states)        | Unmerge must be remembered for future ingests, or the next scan re-merges. Snooze for findings = `accepted` with conditions: expires, **or wakes** when the finding becomes KEV, EPSS crosses a threshold, or the asset becomes internet-facing. This replaces only time-based expiry                 |
| 9   | Honest dashboards: one headline score with benchmarks and Total / Per-source / Per-tag; every tile opens a filtered list; choke points as a ranked list (Tenable) | CTEM dashboard (`features/dashboard/components/ctem/`). Loop tiles link to **unfiltered** pages (`ctem-loop.tsx:105-175`, e.g. `/findings`). Attack paths and exposure chains exist (`attack-paths-card.tsx`, `fix-next-queue.tsx`)                                                                                                                | **Adopt** (drill-down, breakdowns, ranked choke points); **reject** (industry benchmarks) | Every tile carries the exact filter that produced its number. A self-hosted OSS platform has no honest cross-customer population, so a "vs industry" benchmark would be invented. Use the tenant's own trend and targets instead. The headline score follows D12 (formula visible, "not enough data") |
| 10  | Light, dark and high-contrast generated from base, accent and contrast in a perceptual space (Linear LCH)                                                         | Hand-maintained OKLCH tokens per theme (`web/src/styles/theme.css`, about 30 variables × 2); no high-contrast theme; status tokens `success`, `warning`, `info`                                                                                                                                                                                    | **Adopt, later**                                                                          | We are already in OKLCH (Tailwind v4), so a generator is a build-time script that emits the same variables, and the palette-drift gate still applies. The high-contrast theme is the real gain (accessibility). Low urgency: the current two themes are consistent                                    |
| 11  | Empty-state anatomy: image, title, why plus next action, primary action, secondary link (Carbon)                                                                  | `EmptyState` = icon, title, description, action (`features/shared/components/empty-state.tsx:7-14`); contract §7 "Empty"                                                                                                                                                                                                                           | **Already have** + **adopt** (secondary link, three kinds)                                | Add an optional `secondaryAction` (docs link) and name three kinds in the contract (our inference, not sourced): **no data yet** (first use, with the setup action), **no results** (filters active; action "Clear filters"), **not enough data** (metric cannot be computed; never a zero or 100)    |

### 10.2 Proposed contract amendments

The list is diff-style against `web/docs/ui-style-contract.md`.

```diff
 ## 1. Page anatomy
+  - The main sidebar is collapsible and resizable (width persisted per user,
+    min 13rem, max 20rem). Its links are the same in every organization.
+    Settings and the admin console keep their own rail (Settings IA, RFC-022).

 ## 3. Lists and tables
+- Density: `compact` (32px rows) or `comfortable` (40px; multi-line rows
+  such as service rows always use it). Default compact for findings, scans,
+  sensors and single-line asset lists. The choice is a per-user preference
+  (not URL state), set from the table's view menu.
+- Every sortable table has exactly one column sorted by default, shown by the
+  arrow. A newly clicked column sorts ascending; clicking again toggles.
+- Pagination: page size 25/50/100 by default. A list that can exceed 10k rows
+  may offer "Scroll all", which virtualizes rows (`@tanstack/react-virtual`
+  inside `DataTable`) over keyset (cursor) pages from the API. Never load the
+  whole set.
-  - ≥ 3 filter dimensions → `<FacetFilterPanel>` …
+  - ≥ 3 filter dimensions → facets from the server for the current query.
+    Dimensions show their top values with counts; measures (risk, CVSS,
+    EPSS, age) show a range slider. A count is shown only when it is
+    computed with every other active filter applied; otherwise show no count.
+- Bulk actions: while rows are selected, the `BulkActionBar` is the only place
+  to act. Row `⋯` menus are disabled, and the bar always has Clear (Escape
+  works too). Bulk endpoints accept IDs or the list's filter.
+- Saved views: a view stores filter, sort, grouping, columns and density for
+  one page. Personal or team-shared. A view never changes data and is not a
+  group (groups are scan and policy targets).

 ## 2. Headline numbers
+- Every number on a dashboard opens the list it counts, with the same filter.
+- A number that cannot be computed shows "Not enough data" with the reason,
+  never 0 or a perfect score. No industry benchmarks; compare with the
+  tenant's own trend or target.
+- Graph analytics (attack paths, chains) are shown first as a ranked list
+  (choke points by paths × critical assets), with the graph one click away.

 ## 6. Colour
+- Themes: light, dark and high-contrast, generated from base, accent and
+  contrast in OKLCH by `scripts/gen-theme.ts`; `theme.css` is its output.

 ## 7. States
-- **Empty**: the shared `<EmptyState>` (icon, title, one-line description,
-  optional action).
+- **Empty**: the shared `<EmptyState>` (icon, title, why + next step,
+  optional primary action, optional secondary link). Three kinds, each with
+  its own wording: no data yet (setup action), no results (Clear filters),
+  not enough data (what is missing).

+## 10. Triage
+- Findings has an **Inbox** tab: `status=new` in my scope, keyboard actions
+  (confirm, false positive, duplicate, assign). Statuses are mutually
+  exclusive (already true in the API).
+- Duplicates: group by fingerprint; merge and unmerge are explicit, and an
+  unmerge is remembered for later ingests.
+- Snooze is conditional: until a date, or until the finding becomes KEV, its
+  EPSS crosses a threshold, or its asset becomes internet-facing.
```

### 10.3 Order of work

1. **Contract-only, cheap:**
   - default sort everywhere;
   - row menus disabled in batch mode;
   - the three empty-state kinds plus `secondaryAction`;
   - tile drill-down filters on the CTEM dashboard;
   - a resizable sidebar.
2. **With P1 of §5:**
   - disjunctive facets and range sliders;
   - bulk by selector;
   - density modes.
3. **API work first:**
   - saved views;
   - the Findings Inbox tab;
   - merge/unmerge with a remembered unmerge;
   - conditional snooze;
   - keyset pagination, then the virtualized "Scroll all" mode.
4. **Later:** generated themes with high contrast.

## Appendix: method

- **Web and API:** read on `develop` @ `e04bfb35`. File and line references were checked against that tree.
- **Sensor and SDK:** read-only greps of `agent` (`internal/executor/recon.go`, `Dockerfile`) and `sdk-go` (`pkg/scanners/recon/httpx/scanner.go`, `pkg/core/interfaces.go`, `pkg/ctis/recon_converter.go`).
- **Technology metadata:** `github.com/projectdiscovery/wappalyzergo` v0.2.71 in the Go module cache (`fingerprints.go`, `categories_data.json`).
- **In-flight PRs touching these pages:** #829 (honest numbers), #835, #839, #852, #856 and #857 (RFC-036 P0/P1). This plan builds on them and does not duplicate them.
